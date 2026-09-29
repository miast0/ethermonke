#include "capture/capture.hpp"
#include "capture/domain_parser.hpp"
#include "capture/packet_decoder.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <poll.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ethermonke {
namespace {

std::set<std::string> find_local_addresses() {
  std::set<std::string> result;
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) return result;

  for (ifaddrs* item = list; item != nullptr; item = item->ifa_next) {
    if (item->ifa_addr == nullptr) continue;
    std::array<char, INET6_ADDRSTRLEN> output{};
    const void* address = nullptr;
    if (item->ifa_addr->sa_family == AF_INET) {
      address = &reinterpret_cast<const sockaddr_in*>(item->ifa_addr)->sin_addr;
    } else if (item->ifa_addr->sa_family == AF_INET6) {
      address = &reinterpret_cast<const sockaddr_in6*>(item->ifa_addr)->sin6_addr;
    }
    if (address != nullptr &&
        inet_ntop(item->ifa_addr->sa_family, address, output.data(), output.size())) {
      result.emplace(output.data());
    }
  }
  freeifaddrs(list);
  return result;
}

struct TcpConnection {
  std::string remote_address;
  std::uint16_t local_port{};
  std::uint16_t remote_port{};

  auto operator<=>(const TcpConnection&) const = default;
};

struct IcmpEcho {
  std::string remote_address;
  std::uint16_t identifier{};
  std::uint16_t sequence{};

  auto operator<=>(const IcmpEcho&) const = default;
};

struct PendingDomain {
  std::uint32_t next_sequence{};
  std::vector<std::uint8_t> bytes;
};

constexpr std::array<std::uint8_t, 4> http_header_end{'\r', '\n', '\r', '\n'};

}  // namespace

Capture::Capture(std::string interface, NetworkModel& model, MonitorMode mode,
                 const std::vector<ServiceRule>& services)
    : interface_(std::move(interface)), model_(model), mode_(mode),
      services_(services) {}

Capture::~Capture() { stop(); }

bool Capture::start() {
  if (running_) return true;
  std::array<char, PCAP_ERRBUF_SIZE> error_buffer{};
  handle_ = pcap_open_live(interface_.c_str(), 65535, 1, 100, error_buffer.data());
  if (handle_ == nullptr) {
    error_ = error_buffer.data();
    return false;
  }
  if (!supported_link_type(pcap_datalink(handle_))) {
    error_ = "unsupported capture link type on interface " + interface_;
    pcap_close(handle_);
    handle_ = nullptr;
    return false;
  }
  if (pcap_setnonblock(handle_, 1, error_buffer.data()) != 0) {
    error_ = error_buffer.data();
    pcap_close(handle_);
    handle_ = nullptr;
    return false;
  }
  local_addresses_ = find_local_addresses();
  if (local_addresses_.empty()) {
    error_ = "could not determine local IP addresses";
    pcap_close(handle_);
    handle_ = nullptr;
    return false;
  }

  running_ = true;
  thread_ = std::thread(&Capture::run, this);
  return true;
}

void Capture::stop() {
  running_ = false;
  if (thread_.joinable()) thread_.join();
  if (handle_ != nullptr) {
    pcap_close(handle_);
    handle_ = nullptr;
  }
}

void Capture::run() {
  const int link_type = pcap_datalink(handle_);
  const int capture_fd = pcap_get_selectable_fd(handle_);
  std::set<TcpConnection> tcp_connections;
  std::map<TcpConnection, std::chrono::steady_clock::time_point> tcp_syn_times;
  std::map<IcmpEcho, std::chrono::steady_clock::time_point> icmp_echo_times;
  std::map<TcpConnection, std::string> connection_names;
  std::map<TcpConnection, Protocol> connection_protocols;
  std::map<TcpConnection, bool> inbound_tcp_flows;
  std::map<TcpConnection, bool> inbound_udp_flows;
  std::set<IcmpEcho> inbound_echoes;
  std::map<TcpConnection, PendingDomain> pending_domains;
  std::set<TcpConnection> exhausted_domains;
  std::unordered_map<std::string, std::set<std::string>> dns_names;
  bool wait_for_data = true;
  std::size_t packet_count = 0;

  while (running_) {
    if (wait_for_data && capture_fd >= 0) {
      pollfd readable{.fd = capture_fd, .events = POLLIN, .revents = 0};
      const int poll_status = poll(&readable, 1, 100);
      if (poll_status == 0 || (poll_status < 0 && errno == EINTR)) continue;
      if (poll_status < 0) {
        error_ = std::strerror(errno);
        break;
      }
    } else if (wait_for_data) {
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    pcap_pkthdr* header = nullptr;
    const u_char* raw_packet = nullptr;
    const int status = pcap_next_ex(handle_, &header, &raw_packet);
    if (status == 0) {
      wait_for_data = true;
      continue;
    }
    if (status == -1) {
      error_ = pcap_geterr(handle_);
      break;
    }
    if (status != 1 || header == nullptr || raw_packet == nullptr) continue;
    wait_for_data = false;

    const auto decoded = decode_packet(
        link_type,
        {reinterpret_cast<const std::uint8_t*>(raw_packet), header->caplen},
        header->len,
        local_addresses_);
    if (!decoded) continue;
    const auto now = std::chrono::steady_clock::now();
    if (++packet_count % 1024 == 0) {
      std::erase_if(tcp_syn_times, [&](const auto& entry) {
        return now - entry.second > std::chrono::seconds(30);
      });
      std::erase_if(icmp_echo_times, [&](const auto& entry) {
        return now - entry.second > std::chrono::seconds(30);
      });
    }

    if (!decoded->dns_query.empty() && decoded->observation &&
        (mode_ == MonitorMode::host ? !decoded->observation->outbound
                                    : decoded->observation->outbound)) {
      model_.observe_dns_query(decoded->observation->remote_address,
                               decoded->dns_query);
    }

    for (const auto& record : decoded->dns_records) {
      auto& names = dns_names[record.address];
      names.insert(record.hostname);
      if (names.size() == 1) {
        model_.set_domain(record.address, record.hostname, DomainSource::dns);
      }
    }

    if (!decoded->observation) continue;

    Observation observation = *decoded->observation;
    if (mode_ == MonitorMode::host) {
      bool incoming_flow = false;
      if (observation.transport == Transport::tcp) {
        const TcpConnection flow{observation.remote_address,
                                 observation.local_port, observation.remote_port};
        const bool initial_syn = (decoded->tcp_flags & 0x02U) != 0 &&
                                 (decoded->tcp_flags & 0x10U) == 0;
        if (initial_syn) inbound_tcp_flows[flow] = !observation.outbound;
        if (const auto found = inbound_tcp_flows.find(flow);
            found != inbound_tcp_flows.end()) {
          incoming_flow = found->second;
          if (!incoming_flow && (decoded->tcp_flags & 0x05U) != 0) {
            inbound_tcp_flows.erase(found);
          }
        }
      } else if (observation.transport == Transport::udp) {
        const TcpConnection flow{observation.remote_address,
                                 observation.local_port, observation.remote_port};
        incoming_flow = inbound_udp_flows.try_emplace(flow,
                                                       !observation.outbound).first->second;
      } else if (observation.transport == Transport::icmp) {
        const bool echo_request = (decoded->icmp_type == 8 ||
                                   decoded->icmp_type == 128) &&
                                  decoded->icmp_has_echo_fields;
        const bool echo_reply = (decoded->icmp_type == 0 ||
                                 decoded->icmp_type == 129) &&
                                decoded->icmp_has_echo_fields;
        const IcmpEcho echo{observation.remote_address, decoded->icmp_identifier,
                            decoded->icmp_sequence};
        if (echo_request && !observation.outbound) {
          inbound_echoes.insert(echo);
          observation.icmp_echo_request = true;
          incoming_flow = true;
        } else if (echo_reply && observation.outbound) {
          incoming_flow = inbound_echoes.erase(echo) != 0;
        } else if (!echo_request && !echo_reply) {
          incoming_flow = !observation.outbound;
        }
      }
      if (!incoming_flow) continue;
    }
    std::string domain;
    if (observation.transport == Transport::icmp && decoded->icmp_has_echo_fields) {
      const IcmpEcho echo{observation.remote_address, decoded->icmp_identifier,
                          decoded->icmp_sequence};
      if (observation.icmp_echo_request && observation.outbound) {
        icmp_echo_times.try_emplace(echo, now);
      } else if (!observation.outbound &&
                 (decoded->icmp_type == 0 || decoded->icmp_type == 129)) {
        if (const auto found = icmp_echo_times.find(echo);
            found != icmp_echo_times.end()) {
          observation.icmp_rtt_us = static_cast<std::uint64_t>(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  now - found->second).count());
          icmp_echo_times.erase(found);
        }
      }
    }
    if (observation.transport == Transport::tcp) {
      const TcpConnection connection{observation.remote_address,
                                     observation.local_port,
                                     observation.remote_port};
      const bool syn = (decoded->tcp_flags & 0x02U) != 0;
      const bool ack = (decoded->tcp_flags & 0x10U) != 0;
      if (syn && !ack) {
        observation.new_tcp_connection = tcp_connections.insert(connection).second;
        if (observation.outbound) tcp_syn_times.try_emplace(connection, now);
      }
      if (syn && ack && !observation.outbound) {
        if (const auto found = tcp_syn_times.find(connection);
            found != tcp_syn_times.end()) {
          observation.tcp_rtt_us = static_cast<std::uint64_t>(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  now - found->second).count());
          tcp_syn_times.erase(found);
        }
      }
      if (observation.protocol != Protocol::tcp) {
        connection_protocols[connection] = observation.protocol;
      }
      if (!decoded->connection_domain.empty()) {
        connection_names[connection] = decoded->connection_domain;
        pending_domains.erase(connection);
      } else if (observation.outbound && !decoded->tcp_payload.empty() &&
                 !connection_names.contains(connection) &&
                 !exhausted_domains.contains(connection)) {
        auto& pending = pending_domains[connection];
        const auto payload = decoded->tcp_payload;
        std::size_t skip = 0;
        if (pending.bytes.empty()) {
          pending.next_sequence = decoded->tcp_sequence;
        } else if (decoded->tcp_sequence != pending.next_sequence) {
          if (decoded->tcp_sequence < pending.next_sequence) {
            skip = std::min<std::size_t>(pending.next_sequence - decoded->tcp_sequence,
                                         payload.size());
          } else {
            pending.bytes.clear();
            pending.next_sequence = decoded->tcp_sequence;
          }
        }
        if (pending.bytes.size() + payload.size() - skip <= 16384) {
          pending.bytes.insert(pending.bytes.end(), payload.begin() + skip, payload.end());
          pending.next_sequence = std::max(pending.next_sequence,
                                           decoded->tcp_sequence +
                                               static_cast<std::uint32_t>(payload.size()));
          const auto metadata = inspect_connection(pending.bytes);
          if (!metadata.domain.empty()) connection_names[connection] = metadata.domain;
          if (metadata.protocol != Protocol::tcp) {
            connection_protocols[connection] = metadata.protocol;
          }
          const bool incomplete_http_headers = metadata.protocol == Protocol::http &&
              metadata.domain.empty() &&
              std::search(pending.bytes.begin(), pending.bytes.end(),
                          http_header_end.begin(), http_header_end.end()) ==
                  pending.bytes.end();
          if (!metadata.domain.empty() ||
              (metadata.protocol != Protocol::tcp && !incomplete_http_headers)) {
            pending_domains.erase(connection);
          }
        } else {
          pending_domains.erase(connection);
          exhausted_domains.insert(connection);
        }
      }
      if (const auto found = connection_names.find(connection);
          found != connection_names.end()) domain = found->second;
      if (const auto found = connection_protocols.find(connection);
          found != connection_protocols.end()) observation.protocol = found->second;
      if ((decoded->tcp_flags & 0x05U) != 0) {
        inbound_tcp_flows.erase(connection);
        tcp_connections.erase(connection);
        tcp_syn_times.erase(connection);
        connection_names.erase(connection);
        connection_protocols.erase(connection);
        pending_domains.erase(connection);
        exhausted_domains.erase(connection);
      }
    }

    const std::string remote = observation.remote_address;
    if (!domain.empty()) {
      observation.domain = domain;
      model_.set_domain(remote, domain, DomainSource::connection);
    } else if (const auto found = dns_names.find(remote);
               found != dns_names.end() && found->second.size() == 1) {
      observation.domain = *found->second.begin();
      model_.set_domain(remote, observation.domain, DomainSource::dns);
    }
    const std::uint16_t service_port = mode_ == MonitorMode::host
                                           ? observation.local_port
                                           : observation.remote_port;
    for (std::size_t index = 0; index < services_.size(); ++index) {
      const auto& service = services_[index];
      if (service.port == service_port &&
          service_accepts_transport(service.type, observation.transport)) {
        observation.service_index = index;
        observation.protocol = service.type;
        break;
      }
    }
    model_.observe(observation);
  }

  running_ = false;
}

}  // namespace ethermonke
