#include "capture/packet_decoder.hpp"
#include "capture/domain_parser.hpp"

#include <pcap/pcap.h>

#include <arpa/inet.h>

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ethermonke {
namespace {

constexpr std::uint16_t kIpv4 = 0x0800;
constexpr std::uint16_t kIpv6 = 0x86dd;
constexpr std::uint16_t kVlan = 0x8100;
constexpr std::uint16_t kQinQ = 0x88a8;
constexpr std::uint8_t kTcp = 6;
constexpr std::uint8_t kUdp = 17;
constexpr std::uint8_t kIcmpv4 = 1;
constexpr std::uint8_t kIcmpv6 = 58;

std::uint16_t read_u16(const std::uint8_t* bytes) {
  return static_cast<std::uint16_t>((bytes[0] << 8U) | bytes[1]);
}

std::uint32_t read_u32(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
         (static_cast<std::uint32_t>(bytes[1]) << 16U) |
         (static_cast<std::uint32_t>(bytes[2]) << 8U) | bytes[3];
}

std::string address_text(int family, const std::uint8_t* bytes) {
  std::array<char, INET6_ADDRSTRLEN> output{};
  return inet_ntop(family, bytes, output.data(), output.size()) ? output.data() : "";
}

struct NetworkHeader {
  std::size_t offset{};
  std::uint16_t protocol{};
};

bool read_dns_name(std::span<const std::uint8_t> message, std::size_t& cursor,
                   std::string& name) {
  std::size_t position = cursor;
  bool jumped = false;
  for (int parts = 0; parts < 64; ++parts) {
    if (position >= message.size()) return false;
    const std::uint8_t length = message[position++];
    if (length == 0) {
      if (!jumped) cursor = position;
      return !name.empty();
    }
    if ((length & 0xc0U) == 0xc0U) {
      if (position >= message.size()) return false;
      const std::size_t target = ((length & 0x3fU) << 8U) | message[position++];
      if (target >= message.size()) return false;
      if (!jumped) cursor = position;
      jumped = true;
      position = target;
      continue;
    }
    if ((length & 0xc0U) != 0 || length > 63 || position + length > message.size()) {
      return false;
    }
    if (!name.empty()) name += '.';
    for (std::size_t i = 0; i < length; ++i) {
      const char character = static_cast<char>(message[position + i]);
      if ((character >= 'a' && character <= 'z') ||
          (character >= '0' && character <= '9') ||
          character == '-' || character == '_') {
        name += character;
      } else if (character >= 'A' && character <= 'Z') {
        name += static_cast<char>(character - 'A' + 'a');
      } else {
        return false;
      }
    }
    if (name.size() > 253) return false;
    position += length;
    if (!jumped) cursor = position;
  }
  return false;
}

std::vector<DnsRecord> dns_answers(std::span<const std::uint8_t> message) {
  std::vector<DnsRecord> result;
  if (message.size() < 12 || (message[2] & 0x80U) == 0 ||
      (message[3] & 0x0fU) != 0) return result;
  const std::uint16_t question_count = read_u16(message.data() + 4);
  const std::uint16_t answer_count = read_u16(message.data() + 6);
  if (question_count == 0 || question_count > 16 || answer_count > 64) return result;

  std::size_t cursor = 12;
  std::string queried_name;
  for (std::uint16_t i = 0; i < question_count; ++i) {
    std::string name;
    if (!read_dns_name(message, cursor, name) || message.size() < cursor + 4) return {};
    if (i == 0) queried_name = std::move(name);
    cursor += 4;
  }

  for (std::uint16_t i = 0; i < answer_count; ++i) {
    std::string owner;
    if (!read_dns_name(message, cursor, owner) || message.size() < cursor + 10) break;
    const std::uint16_t type = read_u16(message.data() + cursor);
    const std::uint16_t record_class = read_u16(message.data() + cursor + 2);
    const std::uint16_t length = read_u16(message.data() + cursor + 8);
    cursor += 10;
    if (message.size() < cursor + length) break;
    if (record_class == 1 && ((type == 1 && length == 4) ||
                              (type == 28 && length == 16))) {
      const auto address = address_text(type == 1 ? AF_INET : AF_INET6,
                                        message.data() + cursor);
      if (!address.empty()) result.push_back({address, queried_name});
    }
    cursor += length;
  }
  return result;
}

std::string dns_question(std::span<const std::uint8_t> message) {
  if (message.size() < 12 || (message[2] & 0x80U) != 0 ||
      read_u16(message.data() + 4) == 0) return {};
  std::size_t cursor = 12;
  std::string name;
  if (!read_dns_name(message, cursor, name) || message.size() < cursor + 4) return {};
  return name;
}

bool valid_dns_message(std::span<const std::uint8_t> message) {
  if (message.size() < 17 || (message[2] & 0x78U) != 0 ||
      (message[3] & 0x0fU) != 0 || read_u16(message.data() + 4) == 0 ||
      read_u16(message.data() + 4) > 16) return false;
  std::size_t cursor = 12;
  std::string name;
  return read_dns_name(message, cursor, name) && message.size() >= cursor + 4;
}

std::optional<NetworkHeader> network_header(int link_type, std::span<const std::uint8_t> frame) {
  NetworkHeader header;
  if (link_type == DLT_EN10MB) {
    if (frame.size() < 14) return std::nullopt;
    header = {14, read_u16(frame.data() + 12)};
    while (header.protocol == kVlan || header.protocol == kQinQ) {
      if (frame.size() < header.offset + 4) return std::nullopt;
      header.protocol = read_u16(frame.data() + header.offset + 2);
      header.offset += 4;
    }
  } else if (link_type == DLT_LINUX_SLL) {
    if (frame.size() < 16) return std::nullopt;
    header = {16, read_u16(frame.data() + 14)};
  } else if (link_type == DLT_LINUX_SLL2) {
    if (frame.size() < 20) return std::nullopt;
    header = {20, read_u16(frame.data())};
  } else if (link_type == DLT_RAW) {
    if (frame.empty()) return std::nullopt;
    header = {0, static_cast<std::uint16_t>((frame[0] >> 4U) == 4 ? kIpv4 : kIpv6)};
  } else {
    return std::nullopt;
  }
  return header;
}

}  // namespace

bool supported_link_type(int link_type) {
  return link_type == DLT_EN10MB || link_type == DLT_LINUX_SLL ||
         link_type == DLT_LINUX_SLL2 || link_type == DLT_RAW;
}

std::optional<DecodedPacket> decode_packet(int link_type,
                                           std::span<const std::uint8_t> frame,
                                           std::uint32_t wire_bytes,
                                           const std::set<std::string>& local_addresses) {
  const auto link = network_header(link_type, frame);
  if (!link) return std::nullopt;

  std::string source;
  std::string destination;
  std::uint8_t protocol{};
  std::size_t offset{};
  std::size_t network_end = frame.size();

  if (link->protocol == kIpv4) {
    if (frame.size() < link->offset + 20 || (frame[link->offset] >> 4U) != 4) {
      return std::nullopt;
    }
    const std::size_t header_bytes = (frame[link->offset] & 0x0fU) * 4U;
    if (header_bytes < 20 || frame.size() < link->offset + header_bytes) return std::nullopt;
    const std::size_t ip_bytes = read_u16(frame.data() + link->offset + 2);
    if (ip_bytes < header_bytes) return std::nullopt;
    network_end = std::min(frame.size(), link->offset + ip_bytes);
    if ((read_u16(frame.data() + link->offset + 6) & 0x1fffU) != 0) return std::nullopt;
    protocol = frame[link->offset + 9];
    source = address_text(AF_INET, frame.data() + link->offset + 12);
    destination = address_text(AF_INET, frame.data() + link->offset + 16);
    offset = link->offset + header_bytes;
  } else if (link->protocol == kIpv6) {
    if (frame.size() < link->offset + 40 || (frame[link->offset] >> 4U) != 6) {
      return std::nullopt;
    }
    network_end = std::min(frame.size(), link->offset + 40 +
                                            read_u16(frame.data() + link->offset + 4));
    protocol = frame[link->offset + 6];
    source = address_text(AF_INET6, frame.data() + link->offset + 8);
    destination = address_text(AF_INET6, frame.data() + link->offset + 24);
    offset = link->offset + 40;
    for (int extension = 0; extension < 8; ++extension) {
      std::size_t length{};
      if (protocol == 0 || protocol == 43 || protocol == 60) {
        if (network_end < offset + 2) return std::nullopt;
        length = static_cast<std::size_t>(frame[offset + 1] + 1) * 8;
      } else if (protocol == 44) {
        if (network_end < offset + 8) return std::nullopt;
        if ((read_u16(frame.data() + offset + 2) & 0xfff8U) != 0) return std::nullopt;
        length = 8;
      } else if (protocol == 51) {
        if (network_end < offset + 2) return std::nullopt;
        length = static_cast<std::size_t>(frame[offset + 1] + 2) * 4;
      } else {
        break;
      }
      if (network_end < offset + length) return std::nullopt;
      protocol = frame[offset];
      offset += length;
    }
  } else {
    return std::nullopt;
  }

  const bool outbound = local_addresses.contains(source);
  const bool inbound = local_addresses.contains(destination);
  if (protocol == kIcmpv4 || protocol == kIcmpv6) {
    if (network_end < offset + 4 || outbound == inbound) return std::nullopt;
    DecodedPacket decoded;
    decoded.icmp_type = frame[offset];
    const bool echo_request = (protocol == kIcmpv4 && decoded.icmp_type == 8) ||
                              (protocol == kIcmpv6 && decoded.icmp_type == 128);
    const bool echo_reply = (protocol == kIcmpv4 && decoded.icmp_type == 0) ||
                            (protocol == kIcmpv6 && decoded.icmp_type == 129);
    if ((echo_request || echo_reply) && network_end >= offset + 8) {
      decoded.icmp_identifier = read_u16(frame.data() + offset + 4);
      decoded.icmp_sequence = read_u16(frame.data() + offset + 6);
      decoded.icmp_has_echo_fields = true;
    }
    decoded.observation = Observation{
        .remote_address = outbound ? destination : source,
        .domain = {},
        .transport = Transport::icmp,
        .protocol = Protocol::icmp,
        .bytes = wire_bytes,
        .outbound = outbound,
        .icmp_echo_request = outbound && echo_request &&
                             decoded.icmp_has_echo_fields,
    };
    return decoded;
  }
  if (protocol != kTcp && protocol != kUdp) return std::nullopt;
  const std::size_t minimum_bytes = protocol == kTcp ? 20 : 8;
  if (network_end < offset + minimum_bytes) return std::nullopt;

  const std::uint16_t source_port = read_u16(frame.data() + offset);
  const std::uint16_t destination_port = read_u16(frame.data() + offset + 2);
  const std::uint8_t flags = protocol == kTcp ? frame[offset + 13] : 0;
  const std::uint32_t sequence = protocol == kTcp ? read_u32(frame.data() + offset + 4) : 0;
  std::span<const std::uint8_t> tcp_payload;
  std::string observed_domain;
  Protocol observed_protocol = Protocol::tcp;
  if (protocol == kTcp) {
    const std::size_t header_bytes = (frame[offset + 12] >> 4U) * 4U;
    if (header_bytes < 20 || network_end < offset + header_bytes) return std::nullopt;
    if (network_end > offset + header_bytes) {
      tcp_payload = frame.subspan(offset + header_bytes,
                                  network_end - offset - header_bytes);
      const auto metadata = inspect_connection(tcp_payload);
      if (outbound) observed_domain = metadata.domain;
      observed_protocol = metadata.protocol;
    }
  }
  DecodedPacket decoded{
      .observation = std::nullopt,
      .tcp_flags = flags,
      .tcp_sequence = sequence,
      .tcp_payload = tcp_payload,
      .connection_domain = std::move(observed_domain),
      .dns_query = {},
      .dns_records = {},
  };
  if (outbound != inbound) {
    decoded.observation = Observation{
        .remote_address = outbound ? destination : source,
        .domain = {},
        .transport = protocol == kTcp ? Transport::tcp : Transport::udp,
        .protocol = protocol == kTcp ? observed_protocol : Protocol::udp,
        .local_port = outbound ? source_port : destination_port,
        .remote_port = outbound ? destination_port : source_port,
        .bytes = wire_bytes,
        .outbound = outbound,
    };
  }
  if (protocol == kUdp && (source_port == 53 || destination_port == 53)) {
    const std::uint16_t udp_length = read_u16(frame.data() + offset + 4);
    if (udp_length >= 8 && network_end >= offset + udp_length) {
      const auto message = frame.subspan(offset + 8, udp_length - 8);
      if (valid_dns_message(message)) {
        if (decoded.observation) decoded.observation->protocol = Protocol::dns;
        if (source_port == 53) decoded.dns_records = dns_answers(message);
        if (destination_port == 53) decoded.dns_query = dns_question(message);
      }
    }
  }
  if (protocol == kTcp && (source_port == 53 || destination_port == 53) &&
      tcp_payload.size() >= 2) {
    const auto length = read_u16(tcp_payload.data());
    if (length != 0 && tcp_payload.size() >= 2U + static_cast<std::size_t>(length)) {
      const auto message = tcp_payload.subspan(2, length);
      if (valid_dns_message(message)) {
        if (decoded.observation) decoded.observation->protocol = Protocol::dns;
        if (source_port == 53) decoded.dns_records = dns_answers(message);
        if (destination_port == 53) decoded.dns_query = dns_question(message);
      }
    }
  }
  if (!decoded.observation && decoded.dns_records.empty() && decoded.dns_query.empty()) {
    return std::nullopt;
  }
  return decoded;
}

}  // namespace ethermonke
