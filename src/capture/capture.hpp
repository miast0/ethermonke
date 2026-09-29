#pragma once

#include "config/config.hpp"
#include "model/network_model.hpp"

#include <pcap/pcap.h>

#include <atomic>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace ethermonke {

enum class MonitorMode { default_mode, host };

class Capture {
 public:
  Capture(std::string interface, NetworkModel& model, MonitorMode mode,
          const std::vector<ServiceRule>& services);
  ~Capture();

  Capture(const Capture&) = delete;
  Capture& operator=(const Capture&) = delete;

  bool start();
  void stop();
  [[nodiscard]] bool running() const { return running_; }
  [[nodiscard]] const std::string& error() const { return error_; }

 private:
  void run();

  std::string interface_;
  NetworkModel& model_;
  MonitorMode mode_;
  const std::vector<ServiceRule>& services_;
  std::set<std::string> local_addresses_;
  pcap_t* handle_{nullptr};
  std::atomic_bool running_{false};
  std::thread thread_;
  std::string error_;
};

}  // namespace ethermonke
