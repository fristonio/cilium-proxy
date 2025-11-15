#include "cilium/identity_selector.h"

#include <arpa/inet.h>
#include <fmt/format.h>
#include <sys/socket.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/config/subscription.h"
#include "envoy/event/dispatcher.h"
#include "envoy/server/factory_context.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/common/logger.h"
#include "source/common/init/manager_impl.h"

#include "absl/status/status.h"
#include "absl/strings/numbers.h"
#include "cilium/api/isds.pb.h"
#include "cilium/grpc_subscription.h"

namespace Envoy {
namespace Cilium {

uint64_t IdentitySelectorMapImpl::instance_id_ = 0;

IdentitySelectorMapImpl::IdentitySelectorMapImpl(Server::Configuration::FactoryContext& context)
    : context_(context.serverFactoryContext()), map_ptr_(nullptr),
      isds_stats_scope_(context_.serverScope().createScope("cilium.isds.")),
      selector_stats_scope_(context_.serverScope().createScope("cilium.selector.")),

      init_target_(fmt::format("Cilium Identity Selector subscription start"),
                   [this]() {
                     subscription_->start({});
                     // Allow listener init to continue before identity selector updates are
                     // received.
                     init_target_.ready();
                   }),
      transport_factory_context_(
          std::make_shared<Server::Configuration::TransportSocketFactoryContextImpl>(
              context_, *isds_stats_scope_,
              context_.messageValidationContext().dynamicValidationVisitor())),
      stats_{ALL_CILIUM_IDENTITY_SELECTOR_STATS(POOL_COUNTER(*selector_stats_scope_),
                                                POOL_HISTOGRAM(*selector_stats_scope_))} {
  // Use listener init manager for subscription initialization
  context.initManager().add(init_target_);

  // Allocate an initial policy map so that the map pointer is never a nullptr
  store(new RawSelectorMap());
  ENVOY_LOG(trace, "IdentitySelectorMapImpl({}) created.", instance_id_);
}

// IdentitySelectorMapImpl destructor must only be called from the main thread.
IdentitySelectorMapImpl::~IdentitySelectorMapImpl() {
  ENVOY_LOG(debug, "Cilium IdentitySelectorMapImpl({}): IdentitySelectorMap is deleted NOW!",
            instance_id_);
  delete load();
}

void IdentitySelectorMapImpl::startSubscription() {
  subscription_ = subscribe("type.googleapis.com/cilium.IdentitySelector", context_.localInfo(),
                            context_.clusterManager(), context_.mainThreadDispatcher(),
                            context_.api().randomGenerator(), *isds_stats_scope_, *this,
                            std::make_shared<IdentitySelectorDecoder>());
}

// removeInitManager must be called at the end of each selector update.
void IdentitySelectorMapImpl::removeInitManager() {
  // Remove the local init manager from the transport factory context
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnull-dereference"
#endif
  transport_factory_context_->setInitManager(*static_cast<Init::Manager*>(nullptr));
#ifdef __clang__
#pragma clang diagnostic pop
#endif
}

// onConfigUpdate parses the new network policy resources, allocates a new policy map and atomically
// swaps it in place of the old policy map. Throws if any of the 'resources' can not be
// parsed. Otherwise an OK status is returned without pausing ISDS gRPC stream, causing a new
// request (ACK) to be sent immediately.
absl::Status IdentitySelectorMapImpl::onConfigUpdate(
    const std::vector<Envoy::Config::DecodedResourceRef>& resources,
    const std::string& version_info) {
  ENVOY_LOG(debug, "IdentitySelectorMapImpl::onConfigUpdate({}), {} resources, version: {}",
            instance_id_, resources.size(), version_info);
  stats_.updates_total_.inc();

  std::string version_name = fmt::format("IdentitySelectorMap version {}", version_info);
  // Set the init manager to use via the transport factory context
  // Must be set before the new network policy is parsed, as the parsed
  // SDS secrets will use this!
  Init::ManagerImpl version_init_manager(version_name);
  transport_factory_context_->setInitManager(version_init_manager);

  const auto* old_map = load();
  {
    auto new_map = new RawSelectorMap();
    try {
      for (const auto& resource : resources) {
        const auto& config =
            dynamic_cast<const cilium::IdentitySelector&>(resource.get().resource());
        ENVOY_LOG(debug,
                  "Received IdentitySelector with key {} in onConfigUpdate() "
                  "version {}",
                  config.key(), version_info);
        if (config.identities().empty()) {
          throw EnvoyException("Identity Selector has no identities");
        }

        absl::flat_hash_set<uint32_t> id_list(config.identities().begin(),
                                              config.identities().end());
        new_map->emplace(config.key(), id_list);
      }
    } catch (const EnvoyException& e) {
      ENVOY_LOG(warn, "IdentitySelector update for version {} failed: {}", version_info, e.what());
      stats_.updates_rejected_.inc();

      removeInitManager();
      throw; // re-throw
    }
    removeInitManager();

    // Initialize SDS secrets. We do not wait for the completion.
    version_init_manager.initialize(Init::WatcherImpl(version_name, []() {}));

    // Swap the new map in, new_map goes out of scope right after to eliminate accidental
    // modification.
    old_map = exchange(new_map);
  }

  // Delete the old map once all worker threads have entered their event queues, as this
  // is proof that they no longer refer to the old map.
  runAfterAllThreads([old_map]() {
    // Clean-up in the main thread after all threads have scheduled
    delete old_map;
  });

  return absl::OkStatus();
}

absl::Status IdentitySelectorMapImpl::onConfigUpdate(
    const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
    const Protobuf::RepeatedPtrField<std::string>& removed_resources,
    const std::string& system_version_info) {

  ENVOY_LOG(
      debug,
      "IdentitySelectorMapImpl::onDeltaConfigUpdate({}) [Added: {}, Removed: {}, Version: {}]",
      instance_id_, added_resources.size(), removed_resources.size(), system_version_info);
  stats_.updates_total_.inc();

  const auto* old_map = load();
  {
    RawSelectorMap* new_map = new RawSelectorMap(*old_map);
    try {
      for (const auto& selector : removed_resources) {
        uint64_t selector_id = 0;
        if (absl::SimpleAtoi(selector, &selector_id)) {
          new_map->erase(selector_id);
        } else {
          throw EnvoyException(fmt::format("Invalid selector id: {}", selector));
        }
      }

      for (const auto& resource : added_resources) {
        const auto& config =
            dynamic_cast<const cilium::IdentitySelector&>(resource.get().resource());
        if (config.identities().empty()) {
          throw EnvoyException("Identity Selector has no identities");
        }

        absl::flat_hash_set<uint32_t> id_list(config.identities().begin(),
                                              config.identities().end());
        new_map->insert({config.key(), id_list});
      }
    } catch (const EnvoyException& e) {
      ENVOY_LOG(warn, "IdentitySelector update for version {} failed: {}", system_version_info,
                e.what());
      stats_.updates_rejected_.inc();
      throw; // re-throw
    }

    old_map = exchange(new_map);
  }

  runAfterAllThreads([old_map]() { delete old_map; });
  return absl::OkStatus();
}

void IdentitySelectorMapImpl::onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason,
                                                   const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad config.
  ENVOY_LOG(debug, "Identity Selector update failed, keeping existing selectors.");
}

void IdentitySelectorMapImpl::runAfterAllThreads(std::function<void()> cb) const {
  // We can guarantee the callback 'cb' runs in the main thread after all worker threads have
  // entered their event loop, and thus relinquished all state, such as policy lookup results that
  // were stored in their call stack, by posting and empty function to their event queues and
  // waiting until all of them have returned, as managed by 'runOnAllWorkerThreads'.
  //
  // For now we rely on the implementation dependent fact that the reference returned by
  // context_.threadLocal() actually is a ThreadLocal::Instance reference, where
  // runOnAllWorkerThreads() is exposed. Without this cast we'd need to use a dummy thread local
  // variable that would take a thread local slot for no other purpose than to avoid this type cast.
  dynamic_cast<ThreadLocal::Instance&>(context_.threadLocal()).runOnAllWorkerThreads([]() {}, cb);
}

// Common base constructor.
IdentitySelectorMap::IdentitySelectorMap(Server::Configuration::FactoryContext& context)
    : context_(context.serverFactoryContext()) {
  impl_ = std::make_unique<IdentitySelectorMapImpl>(context);

  if (context_.admin().has_value()) {
    ENVOY_LOG(debug, "Registering IdentitySelectors to config tracker");
    config_tracker_entry_ = context_.admin()->getConfigTracker().add(
        "identityselectors", [this](const Matchers::StringMatcher& name_matcher) {
          return dumpIdentitySelectorConfigs(name_matcher);
        });
    RELEASE_ASSERT(config_tracker_entry_, "");
  }
  getImpl().startSubscription();
}

bool IdentitySelectorMap::selects(absl::btree_set<uint64_t> selectors, uint32_t identity) const {
  auto selector_map = getImpl().load();
  for (const auto& selector : selectors) {
    auto it = selector_map->find(selector);
    if (it != selector_map->end() && it->second.find(identity) != it->second.end()) {
      return true;
    }
  }
  return false;
}

IdentitySelectorMap::~IdentitySelectorMap() {
  ENVOY_LOG(debug,
            "Cilium IdentitySelectorMap: posting IdentitySelectorMap deletion to main thread");
  context_.mainThreadDispatcher().post([impl = std::move(impl_)]() {});
}

ProtobufTypes::MessagePtr
IdentitySelectorMap::dumpIdentitySelectorConfigs(const Matchers::StringMatcher& name_matcher) {
  ENVOY_LOG(debug, "Writing IdentitySelectors to IdentitySelectorsConfigDump");

  auto config_dump = std::make_unique<cilium::IdentitySelectorsConfigDump>();
  for (const auto& item : *getImpl().load()) {
    if (!name_matcher.match(fmt::format("{}", item.first))) {
      continue;
    }

    auto id_selector = config_dump->mutable_identityselectors()->Add();
    id_selector->set_key(item.first);
    id_selector->mutable_identities()->Assign(item.second.begin(), item.second.end());
  }

  return config_dump;
}

} // namespace Cilium
} // namespace Envoy
