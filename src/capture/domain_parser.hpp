#pragma once

#include "model/network_model.hpp"

#include <cstdint>
#include <span>
#include <string>

namespace ethermonke {

struct ConnectionMetadata {
  std::string domain;
  Protocol protocol{Protocol::tcp};
};

ConnectionMetadata inspect_connection(std::span<const std::uint8_t> payload);
std::string connection_domain(std::span<const std::uint8_t> payload);

}  // namespace ethermonke
