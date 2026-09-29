#pragma once

#include <chrono>
#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ethermonke {

enum class Transport { tcp, udp, icmp, other };
enum class DomainSource { dns, connection };
enum class Protocol { https, icmp, udp, ssh, ftp, dns, http, tcp, count };

constexpr std::size_t protocol_count = static_cast<std::size_t>(Protocol::count);

struct ProtocolTraffic {
  std::uint64_t bytes_sent{};
  std::uint64_t bytes_received{};
  bool last_outbound{};
  std::chrono::steady_clock::time_point last_seen{};
};

struct Endpoint {
  std::uint64_t first_observed{};
  std::string address;
  std::string hostname;
  DomainSource domain_source{DomainSource::dns};
  std::vector<std::string> addresses;
  std::uint64_t bytes_sent{};
  std::uint64_t bytes_received{};
  std::uint64_t tcp_connections{};
  std::uint64_t tcp_packets{};
  std::uint64_t udp_datagrams{};
  std::uint64_t icmp_echo_requests{};
  std::uint64_t tcp_rtt_total_us{};
  std::uint64_t tcp_rtt_samples{};
  std::uint64_t icmp_rtt_total_us{};
  std::uint64_t icmp_rtt_samples{};
  std::array<ProtocolTraffic, protocol_count> protocols{};
  std::unordered_map<std::size_t, ProtocolTraffic> services;
  bool last_outbound{};
  std::chrono::steady_clock::time_point last_seen{};
};

struct Observation {
  std::string remote_address;
  std::string domain;
  Transport transport{Transport::other};
  Protocol protocol{Protocol::tcp};
  std::optional<std::size_t> service_index{};
  std::uint16_t local_port{};
  std::uint16_t remote_port{};
  std::uint32_t bytes{};
  bool outbound{};
  bool new_tcp_connection{};
  bool icmp_echo_request{};
  std::optional<std::uint64_t> tcp_rtt_us{};
  std::optional<std::uint64_t> icmp_rtt_us{};
};

struct DnsQuery {
  std::string server_address;
  std::string domain;
  std::uint64_t count{};
  std::chrono::steady_clock::time_point last_seen{};
};

class NetworkModel {
 public:
  bool observe(const Observation& observation);
  void set_domain(const std::string& address, std::string domain,
                  DomainSource source);
  void observe_dns_query(const std::string& server_address,
                         const std::string& domain);
  [[nodiscard]] std::vector<Endpoint> snapshot() const;
  [[nodiscard]] std::vector<DnsQuery> query_snapshot() const;

 private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, Endpoint> endpoints_;
  std::unordered_map<std::string, DnsQuery> queries_;
  std::uint64_t next_observed_{};
};

}  // namespace ethermonke
