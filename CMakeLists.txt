cmake_minimum_required(VERSION 3.20)

project(ethermonke VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
find_package(ftxui CONFIG REQUIRED)
find_package(tomlplusplus CONFIG REQUIRED)
find_package(Threads REQUIRED)

add_executable(ethermonke
  src/main.cpp
  src/capture/capture.cpp
  src/capture/packet_decoder.cpp
  src/capture/domain_parser.cpp
  src/config/config.cpp
  src/model/network_model.cpp
  src/ui/graph.cpp
)

target_include_directories(ethermonke PRIVATE src)
target_link_libraries(ethermonke PRIVATE
  PkgConfig::PCAP
  Threads::Threads
  ftxui::component
  ftxui::dom
  ftxui::screen
  tomlplusplus::tomlplusplus
)

target_compile_options(ethermonke PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS ethermonke RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/ethermonke)

set(CPACK_PACKAGE_NAME ethermonke)
set(CPACK_PACKAGE_VENDOR miast0)
set(CPACK_PACKAGE_CONTACT miast0)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
  "Terminal-native network visualisation tool based on EtherApe")
set(CPACK_PACKAGE_DESCRIPTION
  "Terminal-native network visualisation tool based on EtherApe.")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
set(CPACK_GENERATOR "DEB;RPM")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_SECTION net)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_RPM_PACKAGE_AUTOREQPROV ON)
set(CPACK_RPM_PACKAGE_LICENSE CC0-1.0)
set(CPACK_RPM_PACKAGE_RELOCATABLE OFF)
set(CPACK_RPM_PACKAGE_DESCRIPTION
  "Terminal-native network visualisation tool based on EtherApe.")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
include(CPack)
