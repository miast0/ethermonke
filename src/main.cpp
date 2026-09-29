#include "capture/capture.hpp"
#include "config/config.hpp"
#include "model/network_model.hpp"
#include "ui/graph.hpp"

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <pcap/pcap.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

struct Options {
  std::string interface;
  std::string config_path;
  ethermonke::MonitorMode mode{ethermonke::MonitorMode::default_mode};
};

std::string default_interface() {
  std::array<char, PCAP_ERRBUF_SIZE> error_buffer{};
  pcap_if_t* devices = nullptr;
  if (pcap_findalldevs(&devices, error_buffer.data()) != 0) {
    std::cerr << "ethermonke: " << error_buffer.data() << '\n';
    std::exit(1);
  }
  std::string selected;
  std::string fallback;
  for (const pcap_if_t* device = devices; device != nullptr; device = device->next) {
    if (device->name == nullptr || std::string_view(device->name) == "any") continue;
    if ((device->flags & PCAP_IF_LOOPBACK) == 0) {
      if (fallback.empty()) fallback = device->name;
      if ((device->flags & PCAP_IF_UP) != 0) {
        selected = device->name;
        break;
      }
    }
  }
  if (selected.empty()) selected = fallback;
  if (selected.empty() && devices != nullptr && devices->name != nullptr) {
    selected = devices->name;
  }
  pcap_freealldevs(devices);
  if (!selected.empty()) return selected;
  std::cerr << "ethermonke: no capture interfaces found\n";
  std::exit(1);
}

Options parse_options(int argc, char** argv) {
  Options options;
  bool has_interface = false;
  bool has_config = false;
  bool has_mode = false;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "host" && !has_mode) {
      options.mode = ethermonke::MonitorMode::host;
      has_mode = true;
    } else if (argument == "-i" && !has_interface && index + 1 < argc &&
               argv[index + 1][0] != '\0') {
      options.interface = argv[++index];
      has_interface = true;
    } else if (argument == "-c" && !has_config && index + 1 < argc &&
               argv[index + 1][0] != '\0') {
      options.config_path = argv[++index];
      has_config = true;
    } else {
      std::cerr << "usage: ethermonke [host] [-i INTERFACE] [-c CONFIG.toml]\n";
      std::exit(2);
    }
  }
  if (!has_interface) options.interface = default_interface();
  return options;
}

}  // namespace

int main(int argc, char** argv) {
  using namespace ftxui;

  const Options options = parse_options(argc, argv);
  std::vector<ethermonke::ServiceRule> services;
  if (!options.config_path.empty()) {
    try {
      services = ethermonke::load_config(options.config_path);
    } catch (const std::exception& error) {
      std::cerr << "ethermonke: " << error.what() << '\n';
      return 1;
    }
  }
  std::array<char, 256> hostname_buffer{};
  if (gethostname(hostname_buffer.data(), hostname_buffer.size() - 1) != 0) {
    std::cerr << "ethermonke: could not determine hostname\n";
    return 1;
  }
  const std::string local_hostname(hostname_buffer.data());
  ethermonke::NetworkModel model;
  ethermonke::Capture capture(options.interface, model, options.mode, services);
  if (!capture.start()) {
    std::cerr << "ethermonke: " << capture.error() << '\n';
    return 1;
  }

  auto screen = ScreenInteractive::Fullscreen();
  ethermonke::GraphUiState ui;
  std::atomic_bool refreshing{true};
  std::thread refresh([&] {
    while (refreshing) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      screen.PostEvent(Event::Custom);
    }
  });

  auto renderer = Renderer([&] {
    return ethermonke::draw_graph(options.interface, local_hostname, model.snapshot(),
                                 model.query_snapshot(), ui,
                                 options.mode == ethermonke::MonitorMode::host,
                                 services);
  });

  auto app = CatchEvent(renderer, [&](const Event& event) {
    if (event == Event::Custom && !capture.running()) {
      screen.ExitLoopClosure()();
      return true;
    }
    if (event == Event::Character('q') || event == Event::Escape) {
      screen.ExitLoopClosure()();
      return true;
    }
    if (event == Event::Character('?')) {
      ui.graph_only = false;
      ui.show_menu = !ui.show_menu;
      return true;
    }
    if (event == Event::Character('M') || event == Event::Character('m')) {
      ui.graph_only = !ui.graph_only;
      ui.show_menu = false;
      return true;
    }
    if (event == Event::PageDown) {
      if (ui.graph_only) return true;
      ui.details_offset += 5;
      return true;
    }
    if (event == Event::PageUp) {
      if (ui.graph_only) return true;
      ui.details_offset = ui.details_offset > 5 ? ui.details_offset - 5 : 0;
      return true;
    }
    if (event == Event::ArrowDown || event == Event::Character('j')) {
      if (ui.graph_only) return true;
      const auto count = model.snapshot().size();
      if (ui.selected_index + 1 < count) {
        ++ui.selected_index;
        ui.details_offset = 0;
      }
      return true;
    }
    if (event == Event::ArrowUp || event == Event::Character('k')) {
      if (ui.graph_only) return true;
      if (ui.selected_index > 0) {
        --ui.selected_index;
        ui.details_offset = 0;
      }
      return true;
    }
    return false;
  });

  screen.Loop(app);
  refreshing = false;
  refresh.join();
  capture.stop();
  if (!capture.error().empty()) {
    std::cerr << "ethermonke: " << capture.error() << '\n';
    return 1;
  }
  return 0;
}
