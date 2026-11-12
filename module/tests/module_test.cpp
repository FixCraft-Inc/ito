/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// Grammar vectors for the module header and the service names inside it, and
// for the daemon UID option. Expected values are written out from YUME's
// module contract (docs/MODULES.md) and docs/CALL_RELAY.md, not derived from
// the parser under test.

#include "module_header.hpp"

#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "check.hpp"
#include "process.hpp"

namespace {

using namespace ito::module;

std::vector<std::byte> bytes(std::string_view text) {
    std::vector<std::byte> out;
    for (const char character : text)
        out.push_back(static_cast<std::byte>(character));
    return out;
}

const std::string kFingerprint =
    "00112233445566778899aabbccddeeff0123456789abcdef0f1e2d3c4b5a6978";

void test_service_names() {
    for (const std::string_view name : {"ito-call", "a", "a.b", "a-b", "a_b",
                                        "a1.b2-c_d", "yumex", "x.yume", "0"}) {
        CHECK(valid_service_name(name));
    }
    const std::string longest(64U, 'a');
    CHECK(valid_service_name(longest));
    CHECK(!valid_service_name(longest + "a"));
    for (const std::string_view name :
         {"", "A", "Ito", "-a", "a-", "_a", "a_", "a.", ".a", "a..b", "a.-b",
          "a-.b", "a b", "a/b", "yume", "yume.call", "caf\xc3\xa9"}) {
        CHECK(!valid_service_name(name));
    }
    CHECK(!valid_service_name(std::string_view("a\0b", 3U)));
}

void test_header_accepts_exact_line() {
    const auto input =
        bytes("yume-module 1 " + kFingerprint + " ito-call\nREST");
    const auto parsed = parse_module_header(input, "ito-call");
    CHECK(parsed.status == HeaderStatus::Accepted);
    CHECK(parsed.consumed == 14U + 64U + 1U + 8U + 1U);
    const Principal expected{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                             0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                             0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78};
    CHECK(parsed.principal == expected);
    // The bytes after the newline are not part of the header.
    CHECK(std::string_view(
              reinterpret_cast<const char*>(input.data()) + parsed.consumed,
              4U) == "REST");
}

void test_header_is_incomplete_at_every_prefix() {
    const auto input = bytes("yume-module 1 " + kFingerprint + " ito-call\n");
    for (std::size_t length = 0U; length < input.size(); ++length) {
        const auto parsed = parse_module_header(
            std::span<const std::byte>(input.data(), length), "ito-call");
        CHECK(parsed.status == HeaderStatus::Incomplete);
    }
}

void test_header_maximum_length() {
    const std::string service(64U, 's');
    const auto input =
        bytes("yume-module 1 " + kFingerprint + " " + service + "\n");
    CHECK(input.size() == kMaxHeaderBytes);
    CHECK(parse_module_header(input, service).status == HeaderStatus::Accepted);
    // A 65th service byte is refused before any newline arrives.
    const auto longer =
        bytes("yume-module 1 " + kFingerprint + " " + service + "s");
    CHECK(parse_module_header(longer, service).status ==
          HeaderStatus::Malformed);
}

void test_header_refusals() {
    const auto check_status = [](const std::string& text,
                                 HeaderStatus expected) {
        CHECK(parse_module_header(bytes(text), "ito-call").status == expected);
    };
    std::string upper = kFingerprint;
    upper[10] = 'A';
    check_status("yume-module 2 " + kFingerprint + " ito-call\n",
                 HeaderStatus::Malformed);
    check_status("yume-module 1  " + kFingerprint + " ito-call\n",
                 HeaderStatus::Malformed);
    check_status("yume-module 1 " + upper + " ito-call\n",
                 HeaderStatus::Malformed);
    check_status("yume-module 1 " + kFingerprint.substr(0, 63) + " ito-call\n",
                 HeaderStatus::Malformed);
    check_status("yume-module 1 " + kFingerprint + "0 ito-call\n",
                 HeaderStatus::Malformed);
    check_status("yume-module 1 " + kFingerprint + " \n",
                 HeaderStatus::Malformed);
    check_status("yume-module 1 " + kFingerprint + " Ito-call\n",
                 HeaderStatus::Malformed);
    check_status("yume-module 1 " + kFingerprint + " ito-call \n",
                 HeaderStatus::Malformed);
    check_status("yume-module 1 " + kFingerprint + " ito-call\r\n",
                 HeaderStatus::Malformed);
    check_status("yume-module 1 " + kFingerprint + " echo\n",
                 HeaderStatus::OtherService);
    check_status("yume-module 1 " + kFingerprint + " ito-calls\n",
                 HeaderStatus::OtherService);
    // The first wrong byte refuses at once, in the service name as well.
    check_status("YUME", HeaderStatus::Malformed);
    check_status("yume-module 1 0g", HeaderStatus::Malformed);
    check_status("yume-module 1 " + kFingerprint + " ito-C",
                 HeaderStatus::Malformed);
    check_status("yume-module 1 " + kFingerprint + " ito call",
                 HeaderStatus::Malformed);
    check_status("yume-module 1 " + kFingerprint + " ito-c",
                 HeaderStatus::Incomplete);
}

void test_daemon_uid() {
    CHECK(parse_uid("0") == uid_t{0});
    CHECK(parse_uid("999") == uid_t{999});
    CHECK(parse_uid("4294967294") == uid_t{4294967294U});
    for (const std::string_view text :
         {"", "-1", "+1", " 1", "1 ", "0x10", "4294967295", "4294967296",
          "12345678901", "1a"}) {
        CHECK(!parse_uid(text));
    }
}

}  // namespace

int main() {
    test_service_names();
    test_header_accepts_exact_line();
    test_header_is_incomplete_at_every_prefix();
    test_header_maximum_length();
    test_header_refusals();
    test_daemon_uid();
    std::puts("module: all checks passed");
    return 0;
}
