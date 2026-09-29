#include "capture/domain_parser.hpp"

#include <algorithm>
#include <cstddef>
#include <string_view>
#include <utility>

namespace ethermonke {
namespace {

std::size_t read_u16(std::span<const std::uint8_t> data, std::size_t offset) {
  return (static_cast<std::size_t>(data[offset]) << 8U) | data[offset + 1];
}

std::string clean_domain(std::string_view input) {
  if (input.empty() || input.size() > 253) return {};
  if (input.back() == '.') input.remove_suffix(1);
  std::string result;
  result.reserve(input.size());
  for (const unsigned char character : input) {
    if (character >= 'A' && character <= 'Z') {
      result += static_cast<char>(character - 'A' + 'a');
    } else if ((character >= 'a' && character <= 'z') ||
               (character >= '0' && character <= '9') ||
               character == '.' || character == '-' || character == '_') {
      result += static_cast<char>(character);
    } else {
      return {};
    }
  }
  return result;
}

ConnectionMetadata tls_client_hello(std::span<const std::uint8_t> data) {
  ConnectionMetadata result;
  bool encrypted_client_hello = false;
  if (data.size() < 9 || data[0] != 22 || data[1] != 3) return result;
  const std::size_t record_end = 5 + read_u16(data, 3);
  if (record_end > data.size() || data[5] != 1) return result;
  const std::size_t hello_length = (static_cast<std::size_t>(data[6]) << 16U) |
                                   (static_cast<std::size_t>(data[7]) << 8U) | data[8];
  if (9 + hello_length > record_end) return result;
  const std::size_t end = 9 + hello_length;
  std::size_t offset = 9 + 2 + 32;
  if (offset >= end) return result;
  const std::size_t session_id_length = data[offset++];
  offset += session_id_length;
  if (offset + 2 > end) return result;
  offset += 2 + read_u16(data, offset);
  if (offset >= end) return result;
  offset += 1 + data[offset];
  if (offset + 2 > end) return result;
  const std::size_t extensions_end = offset + 2 + read_u16(data, offset);
  offset += 2;
  if (extensions_end > end) return result;

  while (offset + 4 <= extensions_end) {
    const std::size_t type = read_u16(data, offset);
    const std::size_t length = read_u16(data, offset + 2);
    offset += 4;
    if (offset + length > extensions_end) return result;
    if (type == 0xfe0d) encrypted_client_hello = true;
    if (type == 0 && length >= 5) {
      const std::size_t list_end = offset + 2 + read_u16(data, offset);
      if (list_end > offset + length) return result;
      std::size_t name_offset = offset + 2;
      while (name_offset + 3 <= list_end) {
        const std::size_t name_type = data[name_offset++];
        const std::size_t name_length = read_u16(data, name_offset);
        name_offset += 2;
        if (name_offset + name_length > list_end) return result;
        if (name_type == 0) {
          const auto* name = reinterpret_cast<const char*>(data.data() + name_offset);
          result.domain = clean_domain({name, name_length});
          break;
        }
        name_offset += name_length;
      }
    }
    if (type == 16 && length >= 3) {
      const std::size_t list_end = offset + 2 + read_u16(data, offset);
      if (list_end > offset + length) return result;
      std::size_t name_offset = offset + 2;
      while (name_offset < list_end) {
        const std::size_t name_length = data[name_offset++];
        if (name_offset + name_length > list_end) return result;
        const std::string_view name(
            reinterpret_cast<const char*>(data.data() + name_offset), name_length);
        if (name == "h2" || name == "http/1.1") result.protocol = Protocol::https;
        name_offset += name_length;
      }
    }
    offset += length;
  }
  if (encrypted_client_hello) {
    result.domain.clear();
  }
  return result;
}

ConnectionMetadata http_message(std::span<const std::uint8_t> data) {
  ConnectionMetadata result;
  if (data.size() < 12 || data.size() > 8192) return result;
  const std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
  const auto first_line_end = text.find("\r\n");
  if (first_line_end == std::string_view::npos || first_line_end > 1024) return result;
  const auto request_line = text.substr(0, first_line_end);
  const bool response = request_line.starts_with("HTTP/1.0 ") ||
                        request_line.starts_with("HTTP/1.1 ");
  const auto method_end = request_line.find(' ');
  const auto version_start = request_line.rfind(" HTTP/1.");
  const bool request = method_end != std::string_view::npos && method_end != 0 &&
      version_start != std::string_view::npos && version_start > method_end + 1 &&
      (request_line.substr(version_start) == " HTTP/1.0" ||
       request_line.substr(version_start) == " HTTP/1.1") &&
      std::all_of(request_line.begin(), request_line.begin() + method_end,
                  [](char character) { return character >= 'A' && character <= 'Z'; });
  if (!request && !response) return result;
  result.protocol = Protocol::http;
  if (!request) return result;

  std::size_t line_start = first_line_end + 2;
  while (line_start < text.size()) {
    const auto line_end = text.find("\r\n", line_start);
    if (line_end == std::string_view::npos || line_end == line_start) break;
    const auto line = text.substr(line_start, line_end - line_start);
    if (line.size() >= 5 &&
        (line[0] == 'H' || line[0] == 'h') &&
        (line[1] == 'O' || line[1] == 'o') &&
        (line[2] == 'S' || line[2] == 's') &&
        (line[3] == 'T' || line[3] == 't') && line[4] == ':') {
      auto host = line.substr(5);
      while (!host.empty() && host.front() == ' ') host.remove_prefix(1);
      if (const auto colon = host.find(':'); colon != std::string_view::npos) {
        host = host.substr(0, colon);
      }
      result.domain = clean_domain(host);
      return result;
    }
    line_start = line_end + 2;
  }
  if (request_line.starts_with("CONNECT ")) {
    auto target = request_line.substr(8);
    target = target.substr(0, target.find(' '));
    if (const auto colon = target.find(':'); colon != std::string_view::npos) {
      target = target.substr(0, colon);
    }
    result.domain = clean_domain(target);
    return result;
  }
  for (const std::string_view scheme : {"http://", "https://"}) {
    const auto start = request_line.find(scheme);
    if (start == std::string_view::npos) continue;
    auto target = request_line.substr(start + scheme.size());
    target = target.substr(0, target.find_first_of("/: "));
    result.domain = clean_domain(target);
    return result;
  }
  return result;
}

bool ssh_banner(std::span<const std::uint8_t> data) {
  return data.size() >= 4 && data[0] == 'S' && data[1] == 'S' &&
         data[2] == 'H' && data[3] == '-';
}

bool ftp_banner(std::span<const std::uint8_t> data) {
  if (data.size() < 7 || data[0] != '2' || data[1] != '2' || data[2] != '0') {
    return false;
  }
  const std::string_view line(reinterpret_cast<const char*>(data.data()),
                              std::min<std::size_t>(data.size(), 256));
  return line.find("FTP") != std::string_view::npos ||
         line.find("ftp") != std::string_view::npos;
}

}  // namespace

ConnectionMetadata inspect_connection(std::span<const std::uint8_t> payload) {
  if (ssh_banner(payload)) return {.domain = {}, .protocol = Protocol::ssh};
  if (ftp_banner(payload)) return {.domain = {}, .protocol = Protocol::ftp};
  if (auto tls = tls_client_hello(payload);
      !tls.domain.empty() || tls.protocol == Protocol::https) return tls;
  if (auto http = http_message(payload); http.protocol == Protocol::http) {
    return http;
  }
  return {};
}

std::string connection_domain(std::span<const std::uint8_t> payload) {
  return inspect_connection(payload).domain;
}

}  // namespace ethermonke
