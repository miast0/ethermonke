#pragma once

#include "config/config.hpp"
#include "model/network_model.hpp"

#include <ftxui/dom/elements.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace ethermonke {

struct GraphUiState {
  std::size_t selected_index{};
  std::size_t details_offset{};
  bool show_menu{};
  bool graph_only{};
};

ftxui::Element draw_graph(std::string interface, std::string local_hostname,
                          std::vector<Endpoint> endpoints,
                          std::vector<DnsQuery> queries, GraphUiState state,
                          bool host_mode,
                          const std::vector<ServiceRule>& services);

}  // namespace ethermonke
