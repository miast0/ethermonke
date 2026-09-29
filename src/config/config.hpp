#pragma once

#include "model/network_model.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ethermonke {

struct RgbColor {
  std::uint8_t red{};
  std::uint8_t green{};
  std::uint8_t blue{};
};

struct ServiceRule {
  std::string name;
  std::uint16_t port{};
  Protocol type{Protocol::tcp};
  RgbColor node_color{};
  RgbColor transmission_color{};
};

[[nodiscard]] RgbColor default_protocol_color(Protocol protocol);
[[nodiscard]] std::string color_hex(RgbColor color);
[[nodiscard]] bool service_accepts_transport(Protocol type, Transport transport);
[[nodiscard]] std::vector<ServiceRule> load_config(const std::string& path);

}  // namespace ethermonke
