#pragma once

#include <fmt/format.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/common/matchers.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/protobuf/message_validator.h"
#include "envoy/server/config_tracker.h"
#include "envoy/server/factory_context.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/singleton/instance.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h" // IWYU pragma: keep

#include "source/common/common/logger.h"
#include "source/common/common/macros.h"
#include "source/common/init/target_impl.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"
#include "source/server/transport_socket_config_impl.h"

#include "absl/container/btree_set.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "cilium/api/isds.pb.h"
#include "cilium/api/isds.pb.validate.h" // IWYU pragma: keep

namespace Envoy {
namespace Cilium {

class IdentitySelectorDecoder : public Envoy::Config::OpaqueResourceDecoder {
public:
  IdentitySelectorDecoder() : validation_visitor_(ProtobufMessage::getNullValidationVisitor()) {}

  // Config::OpaqueResourceDecoder
  ProtobufTypes::MessagePtr decodeResource(const ProtobufWkt::Any& resource) override {
    auto typed_message = std::make_unique<cilium::IdentitySelector>();
    // If the Any is a synthetic empty message (e.g. because the resource field
    // was not set in Resource, this might be empty, so we shouldn't decode.
    if (!resource.type_url().empty()) {
      MessageUtil::anyConvertAndValidate<cilium::IdentitySelector>(resource, *typed_message,
                                                                   validation_visitor_);
    }
    return typed_message;
  }

  std::string resourceName(const Protobuf::Message& resource) override {
    return fmt::format("{}", dynamic_cast<const cilium::IdentitySelector&>(resource).key());
  }

private:
  ProtobufMessage::ValidationVisitor& validation_visitor_;
};

/**
 * All Cilium Identity Selectors related stats. @see stats_macros.h
 */
// clang-format off
#define ALL_CILIUM_IDENTITY_SELECTOR_STATS(COUNTER, HISTOGRAM)	\
  COUNTER(updates_total)				\
  COUNTER(updates_rejected)
// clang-format on

/**
 * Struct definition for all identity selectors stats. @see stats_macros.h
 */
struct IdentitySelectorStats {
  ALL_CILIUM_IDENTITY_SELECTOR_STATS(GENERATE_COUNTER_STRUCT, GENERATE_HISTOGRAM_STRUCT)
};

using RawSelectorMap = absl::flat_hash_map<uint64_t, absl::flat_hash_set<uint32_t>>;

class IdentitySelectorMapImpl : public Envoy::Config::SubscriptionCallbacks,
                                public Logger::Loggable<Logger::Id::config> {
public:
  IdentitySelectorMapImpl(Server::Configuration::FactoryContext& context);
  ~IdentitySelectorMapImpl() override;

  void startSubscription();

  // This is used for testing with a file-based subscription
  void startSubscription(std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
    subscription_ = std::move(subscription);
  }

  // run the given function after all the threads have scheduled
  void runAfterAllThreads(std::function<void()>) const;

  // Config::SubscriptionCallbacks
  absl::Status onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& resources,
                              const std::string& version_info) override;

  absl::Status onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
                              const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                              const std::string& system_version_info) override;

  void onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason,
                            const EnvoyException* e) override;

  Server::Configuration::TransportSocketFactoryContext& transportFactoryContext() const {
    return *transport_factory_context_;
  }

private:
  const RawSelectorMap* load() const { return map_ptr_.load(std::memory_order_acquire); }
  void store(const RawSelectorMap* map) { map_ptr_.store(map, std::memory_order_release); }
  const RawSelectorMap* exchange(const RawSelectorMap* map) {
    return map_ptr_.exchange(map, std::memory_order_release);
  }

  void removeInitManager();

  static uint64_t instance_id_;

  Server::Configuration::ServerFactoryContext& context_;
  std::atomic<const RawSelectorMap*> map_ptr_;

  Stats::ScopeSharedPtr isds_stats_scope_;
  Stats::ScopeSharedPtr selector_stats_scope_;

  // init target which starts gRPC subscription
  Init::TargetImpl init_target_;
  std::shared_ptr<Server::Configuration::TransportSocketFactoryContextImpl>
      transport_factory_context_;
  std::unique_ptr<Envoy::Config::Subscription> subscription_;

protected:
  friend class IdentitySelectorMap;

  IdentitySelectorStats stats_;
};

class IdentitySelectorMap : public Singleton::Instance,
                            public Logger::Loggable<Logger::Id::config> {
public:
  IdentitySelectorMap(Server::Configuration::FactoryContext& context);
  ~IdentitySelectorMap() override;

  // This is used for testing with a file-based subscription
  void startSubscription(std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
    getImpl().startSubscription(std::move(subscription));
  }

  IdentitySelectorMapImpl& getImpl() const { return *impl_; }

  bool selects(absl::btree_set<uint64_t> selectors, uint32_t identity) const;

private:
  ProtobufTypes::MessagePtr
  dumpIdentitySelectorConfigs(const Matchers::StringMatcher& name_matcher);
  Server::ConfigTracker::EntryOwnerPtr config_tracker_entry_;

  Server::Configuration::ServerFactoryContext& context_;
  std::unique_ptr<IdentitySelectorMapImpl> impl_;
};
using IdentitySelectorMapSharedPtr = std::shared_ptr<const IdentitySelectorMap>;

} // namespace Cilium
} // namespace Envoy
