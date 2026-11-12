/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// Grammar vectors for the requests and the replies. Expected bytes are
// written out from docs/MAILBOX.md, not derived from the encoder under test.

#include "wire.hpp"

#include <cstdio>
#include <vector>

#include "check.hpp"

namespace {

using namespace ito::mailbox;

std::vector<std::byte> frame(std::uint32_t length,
                             const std::vector<std::uint8_t>& body) {
    std::vector<std::byte> out{static_cast<std::byte>(length >> 24U),
                               static_cast<std::byte>(length >> 16U),
                               static_cast<std::byte>(length >> 8U),
                               static_cast<std::byte>(length)};
    for (const auto value : body) out.push_back(std::byte{value});
    return out;
}

// A body of the given length: type, then the payload.
std::vector<std::byte> framed(const std::vector<std::uint8_t>& body) {
    return frame(static_cast<std::uint32_t>(body.size()), body);
}

std::vector<std::uint8_t> counting(std::size_t count, std::uint8_t start) {
    std::vector<std::uint8_t> out;
    for (std::size_t index = 0U; index < count; ++index)
        out.push_back(static_cast<std::uint8_t>(start + index));
    return out;
}

std::vector<std::uint8_t> open_body(std::size_t secrets,
                                    std::uint16_t version = 1U) {
    std::vector<std::uint8_t> body{1U, static_cast<std::uint8_t>(version >> 8U),
                                   static_cast<std::uint8_t>(version)};
    for (std::size_t index = 0U; index < secrets; ++index) {
        const auto secret = counting(32U, static_cast<std::uint8_t>(index));
        body.insert(body.end(), secret.begin(), secret.end());
    }
    return body;
}

std::vector<std::uint8_t> deposit_body(std::uint8_t item_class,
                                       std::uint32_t lifetime,
                                       std::size_t sealed,
                                       std::uint16_t version = 1U) {
    std::vector<std::uint8_t> body{7U, static_cast<std::uint8_t>(version >> 8U),
                                   static_cast<std::uint8_t>(version)};
    const auto address = counting(32U, 0x40U);
    body.insert(body.end(), address.begin(), address.end());
    body.push_back(item_class);
    for (const unsigned shift : {24U, 16U, 8U, 0U})
        body.push_back(static_cast<std::uint8_t>(lifetime >> shift));
    body.insert(body.end(), sealed, 0x5aU);
    return body;
}

RequestStatus status_of(const std::vector<std::byte>& input) {
    return parse_request(input).status;
}

void test_open() {
    const auto one = framed(open_body(1U));
    CHECK(one.size() == 4U + 1U + 2U + 32U);
    auto parsed = parse_request(one);
    CHECK(parsed.status == RequestStatus::Decoded);
    CHECK(parsed.consumed == one.size());
    const auto& open = std::get<OpenRequest>(parsed.request);
    CHECK(open.count() == 1U);
    const auto secret = open.secret(0U);
    CHECK(secret[0] == 0U && secret[31] == 31U);

    const auto most = framed(open_body(512U));
    parsed = parse_request(most);
    CHECK(parsed.status == RequestStatus::Decoded);
    CHECK(std::get<OpenRequest>(parsed.request).count() == 512U);
    CHECK(std::get<OpenRequest>(parsed.request).secret(511U)[0] == 0xffU);

    CHECK(status_of(framed(open_body(513U))) == RequestStatus::Invalid);
    CHECK(status_of(framed(open_body(0U))) == RequestStatus::Invalid);
    auto ragged = open_body(1U);
    ragged.push_back(0U);
    CHECK(status_of(framed(ragged)) == RequestStatus::Invalid);
    CHECK(status_of(framed({1U, 0U})) == RequestStatus::Invalid);
    CHECK(status_of(framed(open_body(1U, 2U))) == RequestStatus::Unsupported);
    // A later version may change the payload, so its length is not checked.
    CHECK(status_of(framed({1U, 0U, 2U})) == RequestStatus::Unsupported);
    CHECK(status_of(framed({1U, 0U, 0U, 7U})) == RequestStatus::Unsupported);
}

void test_taken_close_and_ping() {
    std::vector<std::uint8_t> taken{4U};
    const auto ids = counting(32U, 0x10U);
    taken.insert(taken.end(), ids.begin(), ids.end());
    // A decoded request views its input, so each input outlives its parse.
    const auto taken_input = framed(taken);
    auto parsed = parse_request(taken_input);
    CHECK(parsed.status == RequestStatus::Decoded);
    const auto& request = std::get<TakenRequest>(parsed.request);
    CHECK(request.count() == 2U);
    CHECK(request.id(1U)[0] == 0x20U && request.id(1U)[15] == 0x2fU);
    CHECK(status_of(framed({4U})) == RequestStatus::Invalid);
    taken.push_back(0U);
    CHECK(status_of(framed(taken)) == RequestStatus::Invalid);
    std::vector<std::uint8_t> most{4U};
    most.insert(most.end(), 512U * 16U, 0x01U);
    CHECK(status_of(framed(most)) == RequestStatus::Decoded);
    most.insert(most.end(), 16U, 0x01U);
    CHECK(status_of(framed(most)) == RequestStatus::Invalid);

    std::vector<std::uint8_t> close{5U, 0U, 1U};
    const auto secret = counting(32U, 0x80U);
    close.insert(close.end(), secret.begin(), secret.end());
    const auto close_input = framed(close);
    parsed = parse_request(close_input);
    CHECK(parsed.status == RequestStatus::Decoded);
    CHECK(std::get<CloseRequest>(parsed.request).secret()[0] == 0x80U);
    close.push_back(0U);
    CHECK(status_of(framed(close)) == RequestStatus::Invalid);
    close.pop_back();
    close[2] = 3U;
    CHECK(status_of(framed(close)) == RequestStatus::Unsupported);

    CHECK(status_of(frame(1U, {10U})) == RequestStatus::Decoded);
    CHECK(std::holds_alternative<PingRequest>(
        parse_request(frame(1U, {10U})).request));
    CHECK(status_of(frame(2U, {10U, 0U})) == RequestStatus::Invalid);
}

void test_deposit() {
    for (const std::size_t size : {1024U, 4096U, 16384U}) {
        const auto input = framed(deposit_body(1U, 3600U, size));
        const auto parsed = parse_request(input);
        CHECK(parsed.status == RequestStatus::Decoded);
        CHECK(parsed.consumed == input.size());
        const auto& deposit = std::get<DepositRequest>(parsed.request);
        CHECK(deposit.address[0] == 0x40U && deposit.address[31] == 0x5fU);
        CHECK(deposit.item_class == ItemClass::Message);
        CHECK(deposit.lifetime_seconds == 3600U);
        CHECK(deposit.sealed.size() == size);
        CHECK(deposit.sealed[0] == std::byte{0x5a});
    }
    const auto largest = framed(deposit_body(2U, 60U, 16384U));
    CHECK(largest.size() == 4U + 16424U);
    CHECK(std::get<DepositRequest>(parse_request(largest).request).item_class ==
          ItemClass::Ring);
    for (const std::size_t size : {0U, 1023U, 1025U, 2048U, 4095U, 16383U})
        CHECK(status_of(framed(deposit_body(1U, 60U, size))) ==
              RequestStatus::Invalid);
    CHECK(status_of(framed(deposit_body(0U, 60U, 1024U))) ==
          RequestStatus::Invalid);
    CHECK(status_of(framed(deposit_body(3U, 60U, 1024U))) ==
          RequestStatus::Invalid);
    CHECK(status_of(framed(deposit_body(1U, 0U, 1024U))) ==
          RequestStatus::Invalid);
    CHECK(status_of(framed(deposit_body(1U, 0xffffffffU, 1024U))) ==
          RequestStatus::Decoded);
    CHECK(status_of(framed(deposit_body(1U, 60U, 1024U, 0U))) ==
          RequestStatus::Unsupported);
}

void test_lengths_and_types() {
    // A length outside 1..16424 is refused from its four bytes alone.
    CHECK(status_of(frame(0U, {})) == RequestStatus::Invalid);
    CHECK(status_of(frame(16425U, {})) == RequestStatus::Invalid);
    CHECK(status_of(frame(0xffffffffU, {})) == RequestStatus::Invalid);
    CHECK(status_of(frame(16424U, {7U})) == RequestStatus::Incomplete);
    // Service-only and unknown types.
    for (const unsigned type : {0U, 2U, 3U, 6U, 8U, 9U, 11U, 12U, 13U, 255U})
        CHECK(status_of(frame(1U, {static_cast<std::uint8_t>(type)})) ==
              RequestStatus::Invalid);
}

void test_partial_and_coalesced() {
    const auto deposit = framed(deposit_body(1U, 60U, 1024U));
    for (std::size_t length = 0U; length < deposit.size(); ++length)
        CHECK(parse_request(std::span(deposit.data(), length)).status ==
              RequestStatus::Incomplete);
    auto both = deposit;
    const auto ping = frame(1U, {10U});
    both.insert(both.end(), ping.begin(), ping.end());
    const auto parsed = parse_request(both);
    CHECK(parsed.status == RequestStatus::Decoded);
    CHECK(parsed.consumed == deposit.size());
    CHECK(parse_request(std::span(both).subspan(parsed.consumed)).status ==
          RequestStatus::Decoded);
}

void test_replies() {
    std::array<std::byte, 1024> out{};
    const std::array<Status, 3> statuses{Status::Done, Status::NotHere,
                                         Status::Later};
    CHECK(encode_opened(statuses, out) == 8U);
    CHECK((std::vector<std::byte>(out.begin(), out.begin() + 8) ==
           frame(4U, {2U, 1U, 2U, 3U})));
    CHECK(encode_status(FrameType::Closed, Status::Done, out) == 6U);
    CHECK((std::vector<std::byte>(out.begin(), out.begin() + 6) ==
           frame(2U, {6U, 1U})));
    CHECK(encode_status(FrameType::Rejected, Status::Later, out) == 6U);
    CHECK((std::vector<std::byte>(out.begin(), out.begin() + 6) ==
           frame(2U, {9U, 3U})));
    ItemId id{};
    for (std::size_t index = 0U; index < id.size(); ++index)
        id[index] = static_cast<std::uint8_t>(0xa0U + index);
    CHECK(encode_deposited(id, 60U, out) == 25U);
    auto expected = counting(16U, 0xa0U);
    expected.insert(expected.begin(), 8U);
    expected.insert(expected.end(), {0U, 0U, 0U, 60U});
    CHECK((std::vector<std::byte>(out.begin(), out.begin() + 25) ==
           frame(21U, expected)));
    CHECK(encode_signal(FrameType::Pong, out) == 5U);
    CHECK((std::vector<std::byte>(out.begin(), out.begin() + 5) ==
           frame(1U, {11U})));
    CHECK(encode_refused(RefusalReason::InvalidRequest, out) == 6U);
    CHECK((std::vector<std::byte>(out.begin(), out.begin() + 6) ==
           frame(2U, {12U, 6U})));

    ItemHead head;
    head.item_class = ItemClass::Ring;
    for (std::size_t index = 0U; index < head.address.size(); ++index)
        head.address[index] = static_cast<std::uint8_t>(index);
    head.id = id;
    head.deposit_minute = 0x01020304U;
    head.seconds_left = 59U;
    head.sealed_bytes = 1024U;
    std::array<std::byte, kItemHeadBytes> item{};
    encode_item_head(head, item);
    std::vector<std::uint8_t> body{3U, 2U};
    const auto address = counting(32U, 0U);
    body.insert(body.end(), address.begin(), address.end());
    const auto ids = counting(16U, 0xa0U);
    body.insert(body.end(), ids.begin(), ids.end());
    body.insert(body.end(), {1U, 2U, 3U, 4U, 0U, 0U, 0U, 59U});
    // The length counts the sealed bytes that follow the head.
    CHECK((std::vector<std::byte>(item.begin(), item.end()) ==
           frame(58U + 1024U, body)));
}

}  // namespace

int main() {
    test_open();
    test_taken_close_and_ping();
    test_deposit();
    test_lengths_and_types();
    test_partial_and_coalesced();
    test_replies();
    std::puts("wire: all checks passed");
    return 0;
}
