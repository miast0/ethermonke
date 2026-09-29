#pragma once

#include "model/network_model.hpp"

#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace ethermonke {

struct DnsRecord {
  std::string address;
  std::string hostname;
};

struct DecodedPacket {
  std::optional<Observation> observation;
  std::uint8_t tcp_flags{};
  std::uint32_t tcp_sequence{};
  std::span<const std::uint8_t> tcp_payload;
  std::string connection_domain;
  std::string dns_query;
  std::vector<DnsRecord> dns_records;
  std::uint8_t icmp_type{};
  std::uint16_t icmp_identifier{};
  std::uint16_t icmp_sequence{};
  bool icmp_has_echo_fields{};
};

std::optional<DecodedPacket> decode_packet(int link_type,
                                           std::span<const std::uint8_t> packet,
                                           std::uint32_t wire_bytes,
                                           const std::set<std::string>& local_addresses);

bool supported_link_type(int link_type);

}  // namespace ethermonke
