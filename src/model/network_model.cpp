#include "model/network_model.hpp"

#include <algorithm>
#include <utility>

namespace ethermonke {
namespace {

std::string endpoint_key(const std::string& address, const std::string& domain) {
  return domain.empty() ? address : domain + '\x1f' + address;
}

}  // namespace

bool NetworkModel::observe(const Observation& observation) {
  std::scoped_lock lock(mutex_);
  auto [entry, inserted] = endpoints_.try_emplace(
      endpoint_key(observation.remote_address, observation.domain));
  auto& endpoint = entry->second;
  if (inserted) endpoint.first_observed = next_observed_++;
  endpoint.address = observation.remote_address;
  endpoint.hostname = observation.domain;
  endpoint.last_seen = std::chrono::steady_clock::now();
  endpoint.last_outbound = observation.outbound;
  if (observation.outbound) {
    endpoint.bytes_sent += observation.bytes;
  } else {
    endpoint.bytes_received += observation.bytes;
  }
  auto& traffic = observation.service_index
                      ? endpoint.services[*observation.service_index]
                      : endpoint.protocols[static_cast<std::size_t>(observation.protocol)];
  if (observation.outbound) {
    traffic.bytes_sent += observation.bytes;
  } else {
    traffic.bytes_received += observation.bytes;
  }
  traffic.last_outbound = observation.outbound;
  traffic.last_seen = endpoint.last_seen;
  if (observation.new_tcp_connection) {
    ++endpoint.tcp_connections;
  }
  if (observation.transport == Transport::tcp) ++endpoint.tcp_packets;
  if (observation.transport == Transport::udp) ++endpoint.udp_datagrams;
  if (observation.icmp_echo_request) ++endpoint.icmp_echo_requests;
  if (observation.tcp_rtt_us) {
    endpoint.tcp_rtt_total_us += *observation.tcp_rtt_us;
    ++endpoint.tcp_rtt_samples;
  }
  if (observation.icmp_rtt_us) {
    endpoint.icmp_rtt_total_us += *observation.icmp_rtt_us;
    ++endpoint.icmp_rtt_samples;
  }
  return inserted;
}

void NetworkModel::set_domain(const std::string& address, std::string domain,
                              DomainSource source) {
  std::scoped_lock lock(mutex_);
  const auto found = endpoints_.find(address);
  if (found == endpoints_.end()) return;
  Endpoint old = std::move(found->second);
  endpoints_.erase(found);
  old.hostname = domain;
  old.domain_source = source;
  auto [entry, inserted] = endpoints_.try_emplace(endpoint_key(address, domain),
                                                  std::move(old));
  if (!inserted) {
    auto& endpoint = entry->second;
    endpoint.bytes_sent += old.bytes_sent;
    endpoint.bytes_received += old.bytes_received;
    endpoint.tcp_connections += old.tcp_connections;
    endpoint.first_observed = std::min(endpoint.first_observed,
                                       old.first_observed);
    endpoint.tcp_packets += old.tcp_packets;
    endpoint.udp_datagrams += old.udp_datagrams;
    endpoint.icmp_echo_requests += old.icmp_echo_requests;
    endpoint.tcp_rtt_total_us += old.tcp_rtt_total_us;
    endpoint.tcp_rtt_samples += old.tcp_rtt_samples;
    endpoint.icmp_rtt_total_us += old.icmp_rtt_total_us;
    endpoint.icmp_rtt_samples += old.icmp_rtt_samples;
    for (std::size_t index = 0; index < protocol_count; ++index) {
      auto& target = endpoint.protocols[index];
      const auto& source = old.protocols[index];
      target.bytes_sent += source.bytes_sent;
      target.bytes_received += source.bytes_received;
      if (source.last_seen > target.last_seen) {
        target.last_seen = source.last_seen;
        target.last_outbound = source.last_outbound;
      }
    }
    for (const auto& [index, source] : old.services) {
      auto& target = endpoint.services[index];
      target.bytes_sent += source.bytes_sent;
      target.bytes_received += source.bytes_received;
      if (source.last_seen > target.last_seen) {
        target.last_seen = source.last_seen;
        target.last_outbound = source.last_outbound;
      }
    }
    if (old.last_seen > endpoint.last_seen) {
      endpoint.last_seen = old.last_seen;
      endpoint.last_outbound = old.last_outbound;
    }
  }
}

void NetworkModel::observe_dns_query(const std::string& server_address,
                                     const std::string& domain) {
  std::scoped_lock lock(mutex_);
  auto& query = queries_[server_address + '\x1f' + domain];
  query.server_address = server_address;
  query.domain = domain;
  ++query.count;
  query.last_seen = std::chrono::steady_clock::now();
}

std::vector<Endpoint> NetworkModel::snapshot() const {
  std::scoped_lock lock(mutex_);
  std::vector<Endpoint> result;
  result.reserve(endpoints_.size());
  std::unordered_map<std::string, std::size_t> groups;
  for (const auto& [_, endpoint] : endpoints_) {
    const std::string key = endpoint.hostname.empty() ? endpoint.address : endpoint.hostname;
    auto [entry, inserted] = groups.try_emplace(key, result.size());
    if (inserted) {
      result.push_back(endpoint);
      result.back().addresses = {endpoint.address};
      continue;
    }
    auto& group = result[entry->second];
    group.first_observed = std::min(group.first_observed,
                                    endpoint.first_observed);
    group.addresses.push_back(endpoint.address);
    group.bytes_sent += endpoint.bytes_sent;
    group.bytes_received += endpoint.bytes_received;
    group.tcp_connections += endpoint.tcp_connections;
    group.tcp_packets += endpoint.tcp_packets;
    group.udp_datagrams += endpoint.udp_datagrams;
    group.icmp_echo_requests += endpoint.icmp_echo_requests;
    group.tcp_rtt_total_us += endpoint.tcp_rtt_total_us;
    group.tcp_rtt_samples += endpoint.tcp_rtt_samples;
    group.icmp_rtt_total_us += endpoint.icmp_rtt_total_us;
    group.icmp_rtt_samples += endpoint.icmp_rtt_samples;
    for (std::size_t index = 0; index < protocol_count; ++index) {
      auto& target = group.protocols[index];
      const auto& source = endpoint.protocols[index];
      target.bytes_sent += source.bytes_sent;
      target.bytes_received += source.bytes_received;
      if (source.last_seen > target.last_seen) {
        target.last_seen = source.last_seen;
        target.last_outbound = source.last_outbound;
      }
    }
    for (const auto& [index, source] : endpoint.services) {
      auto& target = group.services[index];
      target.bytes_sent += source.bytes_sent;
      target.bytes_received += source.bytes_received;
      if (source.last_seen > target.last_seen) {
        target.last_seen = source.last_seen;
        target.last_outbound = source.last_outbound;
      }
    }
    if (endpoint.last_seen > group.last_seen) {
      group.last_seen = endpoint.last_seen;
      group.last_outbound = endpoint.last_outbound;
    }
  }
  std::ranges::sort(result, [](const Endpoint& left, const Endpoint& right) {
    return left.first_observed < right.first_observed;
  });
  for (auto& endpoint : result) {
    std::ranges::sort(endpoint.addresses);
    endpoint.address = endpoint.addresses.front();
  }
  return result;
}

std::vector<DnsQuery> NetworkModel::query_snapshot() const {
  std::scoped_lock lock(mutex_);
  std::vector<DnsQuery> result;
  result.reserve(queries_.size());
  for (const auto& [_, query] : queries_) result.push_back(query);
  std::ranges::sort(result, [](const DnsQuery& left, const DnsQuery& right) {
    return left.last_seen > right.last_seen;
  });
  return result;
}

}  // namespace ethermonke
