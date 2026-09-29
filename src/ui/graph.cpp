#include "ui/graph.hpp"

#include <ftxui/dom/canvas.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ethermonke {
namespace {

constexpr double pi = 3.14159265358979323846;

std::string format_bytes(std::uint64_t value) {
  constexpr std::array<const char*, 5> units{"B", "KiB", "MiB", "GiB", "TiB"};
  std::size_t unit = 0;
  double amount = static_cast<double>(value);
  while (amount >= 1024.0 && unit + 1 < units.size()) {
    amount /= 1024.0;
    ++unit;
  }
  return std::to_string(static_cast<std::uint64_t>(amount)) + units[unit];
}

std::string clipped(std::string value, std::size_t limit) {
  if (value.size() <= limit) return value;
  if (limit < 4) return value.substr(0, limit);
  value.resize(limit - 3);
  return value + "...";
}

struct NodePosition {
  int x;
  int y;
  int radius;
};

struct LabelBox {
  int left;
  int top;
  int right;
  int bottom;
};

bool intersects(const LabelBox& a, const LabelBox& b) {
  return a.left < b.right && b.left < a.right && a.top < b.bottom &&
         b.top < a.bottom;
}

void draw_node(ftxui::Canvas& canvas, int x, int y, int radius,
               const ftxui::Color& color) {
  for (int dy = -radius; dy <= radius; ++dy) {
    for (int dx = -radius; dx <= radius; ++dx) {
      if (dx * dx + dy * dy <= radius * radius) {
        canvas.DrawPoint(x + dx, y + dy, true, color);
      }
    }
  }
}

ftxui::Color protocol_color(Protocol protocol) {
  const auto rgb = default_protocol_color(protocol);
  return ftxui::Color::RGB(rgb.red, rgb.green, rgb.blue);
}

ftxui::Color custom_color(RgbColor rgb) {
  return ftxui::Color::RGB(rgb.red, rgb.green, rgb.blue);
}

const char* protocol_name(Protocol protocol) {
  switch (protocol) {
    case Protocol::https: return "HTTPS";
    case Protocol::icmp: return "ICMP";
    case Protocol::udp: return "UDP";
    case Protocol::ssh: return "SSH";
    case Protocol::ftp: return "FTP";
    case Protocol::dns: return "DNS";
    case Protocol::http: return "HTTP";
    case Protocol::tcp: return "TCP";
    case Protocol::count: return "";
  }
  return "";
}

ftxui::Color node_color(const Endpoint& endpoint,
                        const std::vector<ServiceRule>& services) {
  auto color = protocol_color(Protocol::tcp);
  auto latest_seen = endpoint.protocols[static_cast<std::size_t>(Protocol::tcp)].last_seen;
  bool identified = false;
  for (std::size_t index = 0; index < protocol_count; ++index) {
    if (index == static_cast<std::size_t>(Protocol::tcp)) continue;
    const auto& traffic = endpoint.protocols[index];
    if (traffic.bytes_sent + traffic.bytes_received != 0 &&
        (!identified || traffic.last_seen > latest_seen)) {
      latest_seen = traffic.last_seen;
      color = protocol_color(static_cast<Protocol>(index));
      identified = true;
    }
  }
  for (const auto& [index, traffic] : endpoint.services) {
    if (index >= services.size()) continue;
    if (traffic.bytes_sent + traffic.bytes_received != 0 &&
        (!identified || traffic.last_seen > latest_seen)) {
      latest_seen = traffic.last_seen;
      color = custom_color(services[index].node_color);
      identified = true;
    }
  }
  return color;
}

bool has_identified_protocol(const Endpoint& endpoint) {
  if (!endpoint.services.empty()) return true;
  for (std::size_t index = 0; index < protocol_count; ++index) {
    if (index == static_cast<std::size_t>(Protocol::tcp)) continue;
    const auto& traffic = endpoint.protocols[index];
    if (traffic.bytes_sent + traffic.bytes_received != 0) return true;
  }
  return false;
}

struct StyledTraffic {
  const ProtocolTraffic* traffic;
  ftxui::Color transmission_color;
  std::string name;
};

std::vector<StyledTraffic> visible_traffic(
    const Endpoint& endpoint, const std::vector<ServiceRule>& services) {
  std::vector<StyledTraffic> result;
  for (std::size_t index = 0; index < protocol_count; ++index) {
    if (index == static_cast<std::size_t>(Protocol::tcp) &&
        has_identified_protocol(endpoint)) continue;
    const auto& traffic = endpoint.protocols[index];
    if (traffic.bytes_sent + traffic.bytes_received == 0) continue;
    result.push_back({&traffic, protocol_color(static_cast<Protocol>(index)),
                      protocol_name(static_cast<Protocol>(index))});
  }
  for (std::size_t index = 0; index < services.size(); ++index) {
    const auto found = endpoint.services.find(index);
    if (found == endpoint.services.end()) continue;
    const auto& traffic = found->second;
    if (traffic.bytes_sent + traffic.bytes_received == 0) continue;
    result.push_back({&traffic, custom_color(services[index].transmission_color),
                      services[index].name});
  }
  return result;
}

std::string format_rtt(std::uint64_t total_us, std::uint64_t samples) {
  if (samples == 0) return "n/a";
  const auto average_us = total_us / samples;
  if (average_us >= 1000) return std::to_string(average_us / 1000) + "ms";
  return std::to_string(average_us) + "us";
}

double preferred_radius_scale(const Endpoint& endpoint, int node_radius) {
  constexpr std::array<double, 4> radii{0.24, 0.29, 0.34, 0.39};
  std::size_t ring = static_cast<std::size_t>(endpoint.first_observed % radii.size());
  double latency_fraction = 0.0;
  std::uint64_t latency_us = 0;
  bool measured_rtt = false;
  if (endpoint.icmp_rtt_samples != 0) {
    latency_us = endpoint.icmp_rtt_total_us / endpoint.icmp_rtt_samples;
    measured_rtt = true;
  } else if (endpoint.tcp_rtt_samples != 0) {
    latency_us = endpoint.tcp_rtt_total_us / endpoint.tcp_rtt_samples;
    measured_rtt = true;
  }
  if (measured_rtt) {
    const double latency_ms = static_cast<double>(latency_us) / 1000.0;
    latency_fraction = std::clamp(std::log1p(latency_ms) / std::log1p(1000.0),
                                  0.0, 1.0);
    ring = std::min(radii.size() - 1,
                    static_cast<std::size_t>(latency_fraction * radii.size()));
  }
  return std::min(0.43, radii[ring] * (1.0 + 0.08 * latency_fraction) +
                            0.002 * static_cast<double>(node_radius - 3));
}

}  // namespace

ftxui::Element draw_graph(std::string interface, std::string local_hostname,
                          std::vector<Endpoint> endpoints,
                          std::vector<DnsQuery> queries, GraphUiState state,
                          bool host_mode,
                          const std::vector<ServiceRule>& services) {
  using namespace ftxui;

  const std::size_t count = endpoints.size();
  const std::size_t selected_index = std::min(state.selected_index,
                                               count == 0 ? 0 : count - 1);
  const Endpoint* selected = count == 0 ? nullptr : &endpoints[selected_index];
  std::uint64_t total_sent = 0;
  std::uint64_t total_received = 0;
  std::uint64_t total_tcp_connections = 0;
  std::uint64_t total_udp_datagrams = 0;
  for (const auto& endpoint : endpoints) {
    total_sent += endpoint.bytes_sent;
    total_received += endpoint.bytes_received;
    total_tcp_connections += endpoint.tcp_connections;
    total_udp_datagrams += endpoint.udp_datagrams;
  }

  std::string detail = "No hosts observed yet";
  std::string protocols;
  std::vector<DnsQuery> dns_domains;
  if (selected != nullptr) {
    detail = "[" + (selected->hostname.empty() ? selected->address : selected->hostname) + "]" +
             "  |  TCP connections " + std::to_string(selected->tcp_connections) +
             "  |  sent " + format_bytes(selected->bytes_sent) +
             "  received " + format_bytes(selected->bytes_received);
    for (const auto& traffic : visible_traffic(*selected, services)) {
      if (!protocols.empty()) protocols += "  ";
      protocols += traffic.name;
    }
    for (const auto& query : queries) {
      if (std::find(selected->addresses.begin(), selected->addresses.end(),
                    query.server_address) != selected->addresses.end()) {
        dns_domains.push_back(query);
      }
    }
  }

  auto graph = canvas([endpoints = std::move(endpoints), selected_index,
                       graph_only = state.graph_only,
                       host_mode,
                       services,
                       local_hostname = std::move(local_hostname)](Canvas& c) {
    const int width = c.width();
    const int height = c.height();
    const int cx = width / 2;
    const int cy = height / 2;
    const std::size_t count = endpoints.size();
    const auto now = std::chrono::steady_clock::now();
    std::uint64_t busiest_bytes = 0;
    for (const auto& endpoint : endpoints) {
      busiest_bytes = std::max(busiest_bytes,
                               endpoint.bytes_sent + endpoint.bytes_received);
    }
    const int max_radius = std::max(3, std::min(14, height / 6));
    const int busiest_radius = std::clamp(
        4 + static_cast<int>(std::floor(2.0 * std::log2(
                1.0 + static_cast<double>(busiest_bytes) / 32768.0))),
        3, max_radius);
    std::vector<std::optional<NodePosition>> positions(count);
    for (std::size_t index = 0; index < count; ++index) {
      const auto& endpoint = endpoints[index];
      const double bytes = static_cast<double>(endpoint.bytes_sent) +
                           static_cast<double>(endpoint.bytes_received);
      const double share = busiest_bytes == 0 ? 0.0 :
          std::sqrt(bytes / static_cast<double>(busiest_bytes));
      const int radius = 3 + static_cast<int>(std::floor(
          static_cast<double>(busiest_radius - 3) * share));
      const double preferred_scale = preferred_radius_scale(endpoint, radius);
      const double sector = 2.0 * pi / static_cast<double>(count);
      const double base_angle = -pi / 2.0 + sector *
                                    (static_cast<double>(index) + 0.5);
      std::optional<NodePosition> best;
      double best_penalty = std::numeric_limits<double>::infinity();
      for (int offset = 0; offset < 5 && !positions[index]; ++offset) {
        const double angle = base_angle + sector *
            (offset == 0 ? 0.0 : (offset % 2 ? 1.0 : -1.0) *
                                    static_cast<double>((offset + 1) / 2) / 8.0);
        for (int step = 0; step < 13 && !positions[index]; ++step) {
          const double adjustment = step == 0 ? 0.0 :
              (step % 2 ? 1.0 : -1.0) *
                  static_cast<double>((step + 1) / 2) * 0.015;
          const double scale = std::clamp(preferred_scale + adjustment,
                                          0.16, 0.44);
          const int x = 2 * static_cast<int>(std::lround(
              (cx + std::cos(angle) * width * scale) / 2.0));
          const int y = 4 * static_cast<int>(std::lround(
              (cy + std::sin(angle) * height * scale) / 4.0));
          if (x - radius < 2 || x + radius >= width - 2 ||
              y - radius < 2 || y + radius >= height - 2 ||
              std::hypot(static_cast<double>(x - cx),
                         static_cast<double>(y - cy)) < radius + 12) continue;
          double penalty = 0.0;
          for (const auto& other : positions) {
            if (!other) continue;
            const double distance = std::hypot(static_cast<double>(x - other->x),
                                               static_cast<double>(y - other->y));
            penalty += std::max(0.0, radius + other->radius + 5.0 - distance);
          }
          if (penalty < best_penalty) {
            best_penalty = penalty;
            best = NodePosition{x, y, radius};
          }
          if (penalty == 0.0) positions[index] = NodePosition{x, y, radius};
        }
      }
      if (!positions[index]) {
        positions[index] = best.value_or(NodePosition{
            std::clamp(cx, radius + 2, std::max(radius + 2, width - radius - 2)),
            std::clamp(cy, radius + 2, std::max(radius + 2, height - radius - 2)),
            radius});
      }
    }
    for (std::size_t index = 0; index < count; ++index) {
      const auto& node = *positions[index];
      const int x = node.x;
      const int y = node.y;
      const auto& endpoint = endpoints[index];
      const auto lines = visible_traffic(endpoint, services);
      const double length = std::max(1.0, std::hypot(static_cast<double>(x - cx),
                                                     static_cast<double>(y - cy)));
      for (std::size_t line = 0; line < lines.size(); ++line) {
        const auto& traffic = *lines[line].traffic;
        const auto color = lines[line].transmission_color;
        const double separation = (static_cast<double>(line) -
                                   (static_cast<double>(lines.size()) - 1.0) / 2.0) * 2.0;
        const int shift_x = static_cast<int>(-(y - cy) * separation / length);
        const int shift_y = static_cast<int>((x - cx) * separation / length);
        const double start = std::min(1.0, 9.0 / length);
        const int start_x = cx + static_cast<int>((x - cx) * start) + shift_x;
        const int start_y = cy + static_cast<int>((y - cy) * start) + shift_y;
        c.DrawPointLine(start_x, start_y, x + shift_x, y + shift_y, color);
        if (now - traffic.last_seen < std::chrono::seconds(2)) {
          const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        now.time_since_epoch()).count();
          double progress = start + (1.0 - start) *
                              static_cast<double>(milliseconds % 900) / 900.0;
          if (host_mode || !traffic.last_outbound) progress = 1.0 - progress;
          c.DrawPointCircleFilled(
              cx + shift_x + static_cast<int>((x - cx) * progress),
              cy + shift_y + static_cast<int>((y - cy) * progress), 2, color);
        }
      }
    }

    draw_node(c, cx, cy, 5, Color::Cyan);
    const int hostname_x = std::clamp(cx + 8, 0, std::max(0, width - 2));
    const std::size_t hostname_limit = static_cast<std::size_t>(
        std::max(1, (width - hostname_x) / 2));
    c.DrawText(hostname_x, cy, clipped(local_hostname, hostname_limit), Color::Cyan);
    for (std::size_t index = 0; index < count; ++index) {
      const auto& node = *positions[index];
      draw_node(c, node.x, node.y, node.radius,
                node_color(endpoints[index], services));
    }

    std::vector<LabelBox> occupied;
    occupied.push_back({cx - 12, cy - 5, cx + 32, cy + 8});
    // Draw the selected label first so it remains visible in a crowded graph.
    for (std::size_t order = 0; order < count; ++order) {
      std::size_t index = order;
      if (!graph_only && selected_index < count) {
        if (order == 0) index = selected_index;
        else if (order <= selected_index) index = order - 1;
      }
      const auto& endpoint = endpoints[index];
      const auto& node = *positions[index];
      const bool selected_node = !graph_only && index == selected_index;
      const std::size_t max_chars = static_cast<std::size_t>(
          std::min(std::clamp(width / 8, 4, 32), std::max(1, (width - 4) / 2)));
      std::string name = clipped(
          endpoint.hostname.empty() ? endpoint.address : endpoint.hostname,
          max_chars - (selected_node && max_chars > 2 ? 2 : 0));
      if (selected_node) name = "[" + name + "]";
      const int label_width = static_cast<int>(name.size() * 2);
      const int label_height = 4;
      const bool right = node.x >= cx;
      int x = right ? node.x + node.radius + 4 : node.x - node.radius - 4 - label_width;
      x = std::clamp(x, 0, std::max(0, width - label_width));
      int y = std::clamp(node.y - label_height / 2, 0,
                         std::max(0, height - label_height));
      // Keep labels close to their nodes; distant aligned callouts turn the
      // graph back into a list when the terminal is crowded.
      bool placed = false;
      for (int offset = 0; offset <= 2; ++offset) {
        for (int direction : {1, -1}) {
          const int candidate_y = y + direction * offset * 4;
          if (candidate_y < 0 || candidate_y + label_height > height) continue;
          const LabelBox box{x, candidate_y, x + label_width, candidate_y + label_height};
          if (std::none_of(occupied.begin(), occupied.end(),
                           [&](const LabelBox& other) { return intersects(box, other); })) {
            y = candidate_y;
            occupied.push_back(box);
            placed = true;
            break;
          }
        }
        if (placed) break;
      }
      if (!placed && !selected_node) continue;
      const Color label_color = selected_node ? Color::Cyan :
                                node_color(endpoint, services);
      c.DrawText(x, y, name, label_color);
    }
  });

  if (state.graph_only) return vbox({graph | flex}) | flex;

  Elements body;
  body.push_back(hbox({text(host_mode ? " ethermonke host " : " ethermonke ") |
                          bold | color(Color::Cyan),
                      text("  " + interface) | dim, filler(),
                      text(std::to_string(count) + " hosts  ") | dim,
                      text("? Menu ") | color(Color::Cyan)}));
  body.push_back(separator());
  body.push_back(graph | flex);
  body.push_back(separator());
  body.push_back(text(" " + detail));
  if (selected != nullptr) {
    constexpr std::size_t page_size = 5;
    if (!selected->addresses.empty()) {
      const std::size_t max_offset =
          ((selected->addresses.size() - 1) / page_size) * page_size;
      const std::size_t offset = std::min(state.details_offset, max_offset);
      body.push_back(text(" IP addresses (" + std::to_string(offset + 1) + "-" +
                          std::to_string(std::min(offset + page_size,
                                                  selected->addresses.size())) +
                          "/" + std::to_string(selected->addresses.size()) +
                          "; PgUp/PgDn):") | dim);
      for (std::size_t index = offset;
           index < std::min(offset + page_size, selected->addresses.size()); ++index) {
        body.push_back(text("  [" + selected->addresses[index] + "]") | dim);
      }
    }
    body.push_back(text(" Protocols: " + protocols) | dim);
    body.push_back(text(" TCP  connections " +
                        std::to_string(selected->tcp_connections) +
                        "  packets " + std::to_string(selected->tcp_packets) +
                        "  handshake RTT " +
                        format_rtt(selected->tcp_rtt_total_us,
                                   selected->tcp_rtt_samples)));
    body.push_back(text(" UDP  datagrams " +
                        std::to_string(selected->udp_datagrams) +
                        "    ICMP echo requests " +
                        std::to_string(selected->icmp_echo_requests) +
                        "  echo RTT " +
                        format_rtt(selected->icmp_rtt_total_us,
                                   selected->icmp_rtt_samples)));
  }
  if (!dns_domains.empty()) {
    constexpr std::size_t page_size = 5;
    const std::size_t max_offset = ((dns_domains.size() - 1) / page_size) * page_size;
    const std::size_t offset = std::min(state.details_offset, max_offset);
    body.push_back(text(" DNS questions to this server (" +
                        std::to_string(offset + 1) + "-" +
                        std::to_string(std::min(offset + page_size, dns_domains.size())) +
                        "/" + std::to_string(dns_domains.size()) +
                        "; PgUp/PgDn):") | color(protocol_color(Protocol::dns)));
    for (std::size_t index = offset;
         index < std::min(offset + page_size, dns_domains.size()); ++index) {
      const auto& query = dns_domains[index];
      body.push_back(text("  " + query.domain + "  x" +
                          std::to_string(query.count)));
    }
  }
  body.push_back(hbox({text(" sent " + format_bytes(total_sent) + "  received " +
                             format_bytes(total_received) +
                             "  TCP " + std::to_string(total_tcp_connections) +
                             "  UDP " + std::to_string(total_udp_datagrams)) | dim,
                       filler(), text("j/k select  M graph only  q quit ") | dim}));
  auto main_view = vbox(std::move(body)) | border | flex;
  if (!state.show_menu) return main_view;

  Elements menu_rows;
  menu_rows.push_back(text(" Menu  [?] close") | bold);
  menu_rows.push_back(separator());
  for (const auto& service : services) {
    menu_rows.push_back(text(" " + service.name + "  " +
                             color_hex(service.node_color)) |
                        color(custom_color(service.node_color)));
    if (color_hex(service.node_color) != color_hex(service.transmission_color)) {
      menu_rows.push_back(text("   line  " +
                               color_hex(service.transmission_color)) |
                          color(custom_color(service.transmission_color)));
    }
  }
  if (!services.empty()) menu_rows.push_back(separator());
  menu_rows.push_back(text(" HTTPS  #22FCD1") | color(protocol_color(Protocol::https)));
  menu_rows.push_back(text(" ICMP   #22BBFC") | color(protocol_color(Protocol::icmp)));
  menu_rows.push_back(text(" UDP    #22FC63") | color(protocol_color(Protocol::udp)));
  menu_rows.push_back(text(" SSH    #CB1FFF") | color(protocol_color(Protocol::ssh)));
  menu_rows.push_back(text(" FTP    #CB1FFF") | color(protocol_color(Protocol::ftp)));
  menu_rows.push_back(text(" DNS    #FF1FC3") | color(protocol_color(Protocol::dns)));
  menu_rows.push_back(text(" HTTP   #4DD153") | color(protocol_color(Protocol::http)));
  menu_rows.push_back(text(" TCP    default") | color(protocol_color(Protocol::tcp)));
  menu_rows.push_back(separator());
  menu_rows.push_back(text(" j/k       hosts") | dim);
  menu_rows.push_back(text(" PgUp/PgDn details") | dim);
  menu_rows.push_back(text(" M         graph") | dim);
  menu_rows.push_back(text(" q         quit") | dim);
  menu_rows.push_back(filler());
  auto menu = vbox(std::move(menu_rows)) | borderRounded | size(WIDTH, EQUAL, 26);
  return hbox({main_view, menu});
}

}  // namespace ethermonke
