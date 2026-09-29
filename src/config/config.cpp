#include "config/config.hpp"

#include <toml++/toml.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace ethermonke {
namespace {

int hex_digit(char character) {
  if (character >= '0' && character <= '9') return character - '0';
  if (character >= 'a' && character <= 'f') return character - 'a' + 10;
  if (character >= 'A' && character <= 'F') return character - 'A' + 10;
  return -1;
}

RgbColor parse_color(std::string_view value, std::string_view field,
                     std::size_t service_number) {
  if (value.size() != 7 || value[0] != '#') {
    throw std::runtime_error("service " + std::to_string(service_number) +
                             ": " + std::string(field) + " must be #RRGGBB");
  }
  std::array<std::uint8_t, 3> channels{};
  for (std::size_t index = 0; index < channels.size(); ++index) {
    const int high = hex_digit(value[1 + index * 2]);
    const int low = hex_digit(value[2 + index * 2]);
    if (high < 0 || low < 0) {
      throw std::runtime_error("service " + std::to_string(service_number) +
                               ": " + std::string(field) + " must be #RRGGBB");
    }
    channels[index] = static_cast<std::uint8_t>(high * 16 + low);
  }
  return {channels[0], channels[1], channels[2]};
}

std::optional<Protocol> parse_type(std::string_view value) {
  if (value == "https") return Protocol::https;
  if (value == "icmp") return Protocol::icmp;
  if (value == "udp") return Protocol::udp;
  if (value == "ssh") return Protocol::ssh;
  if (value == "ftp") return Protocol::ftp;
  if (value == "dns") return Protocol::dns;
  if (value == "http") return Protocol::http;
  if (value == "tcp") return Protocol::tcp;
  return std::nullopt;
}

std::optional<RgbColor> optional_color(const toml::table& table,
                                       std::string_view key,
                                       std::size_t service_number) {
  const toml::node* node = table.get(key);
  if (node == nullptr) return std::nullopt;
  const auto value = node->value<std::string>();
  if (!value) {
    throw std::runtime_error("service " + std::to_string(service_number) +
                             ": " + std::string(key) + " must be a string");
  }
  return parse_color(*value, key, service_number);
}

}  // namespace

RgbColor default_protocol_color(Protocol protocol) {
  switch (protocol) {
    case Protocol::https: return {0x22, 0xfc, 0xd1};
    case Protocol::icmp: return {0x22, 0xbb, 0xfc};
    case Protocol::udp: return {0x22, 0xfc, 0x63};
    case Protocol::ssh:
    case Protocol::ftp: return {0xcb, 0x1f, 0xff};
    case Protocol::dns: return {0xff, 0x1f, 0xc3};
    case Protocol::http: return {0x4d, 0xd1, 0x53};
    case Protocol::tcp:
    case Protocol::count: return {0xff, 0xff, 0xff};
  }
  return {0xff, 0xff, 0xff};
}

std::string color_hex(RgbColor color) {
  constexpr char digits[] = "0123456789ABCDEF";
  std::string result = "#000000";
  const std::array<std::uint8_t, 3> channels{color.red, color.green, color.blue};
  for (std::size_t index = 0; index < channels.size(); ++index) {
    result[1 + index * 2] = digits[channels[index] >> 4U];
    result[2 + index * 2] = digits[channels[index] & 0x0fU];
  }
  return result;
}

bool service_accepts_transport(Protocol type, Transport transport) {
  switch (type) {
    case Protocol::udp: return transport == Transport::udp;
    case Protocol::dns:
    case Protocol::https: return transport == Transport::tcp ||
                                 transport == Transport::udp;
    case Protocol::http:
    case Protocol::ssh:
    case Protocol::ftp:
    case Protocol::tcp: return transport == Transport::tcp;
    case Protocol::icmp:
    case Protocol::count: return false;
  }
  return false;
}

std::vector<ServiceRule> load_config(const std::string& path) {
  const toml::table document = toml::parse_file(path);
  std::vector<ServiceRule> result;
  const toml::node* service_node = document.get("service");
  if (service_node == nullptr) return result;
  const toml::array* services = service_node->as_array();
  if (services == nullptr) {
    throw std::runtime_error("service must be an array of [[service]] tables");
  }
  result.reserve(services->size());
  for (const toml::node& node : *services) {
    const std::size_t number = result.size() + 1;
    const toml::table* table = node.as_table();
    if (table == nullptr) {
      throw std::runtime_error("service " + std::to_string(number) +
                               " must be a table");
    }
    const auto name = (*table)["name"].value<std::string>();
    const auto port = (*table)["port"].value<std::int64_t>();
    const auto type_name = (*table)["type"].value<std::string>();
    if (!name || name->empty()) {
      throw std::runtime_error("service " + std::to_string(number) +
                               ": name must be a nonempty string");
    }
    if (!port || *port < 1 || *port > 65535) {
      throw std::runtime_error("service " + std::to_string(number) +
                               ": port must be an integer from 1 to 65535");
    }
    const auto type = type_name ? parse_type(*type_name) : std::nullopt;
    if (!type || *type == Protocol::icmp) {
      throw std::runtime_error("service " + std::to_string(number) +
                               ": type must be a port-based protocol");
    }
    ServiceRule rule;
    rule.name = *name;
    rule.port = static_cast<std::uint16_t>(*port);
    rule.type = *type;
    const RgbColor fallback = optional_color(*table, "color", number)
                                  .value_or(default_protocol_color(*type));
    rule.node_color = optional_color(*table, "node-color", number)
                          .value_or(fallback);
    rule.transmission_color = optional_color(*table, "transmission-color", number)
                                  .value_or(fallback);
    result.push_back(std::move(rule));
  }
  return result;
}

}  // namespace ethermonke
