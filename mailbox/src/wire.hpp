/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The version-1 frames of docs/MAILBOX.md. module_header.hpp parses the
// module header before them. Parsing is pure, bounded and allocation free. A
// decoded request holds views into the caller's input, valid until the
// caller consumes those bytes, so a 16 KiB deposit is never copied to be
// parsed.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>

#include "sha256.hpp"

namespace ito::mailbox {

using ItemId = std::array<std::uint8_t, 16>;

inline constexpr std::size_t kFrameLengthBytes = 4U;
inline constexpr std::uint16_t kProtocolVersion = 1U;
inline constexpr std::size_t kSecretBytes = 32U;
inline constexpr std::size_t kItemIdBytes = 16U;
inline constexpr std::size_t kMaxSecretsPerOpen = 512U;
inline constexpr std::size_t kMaxIdsPerTaken = 512U;
inline constexpr std::size_t kSmallItemBytes = 1024U;
inline constexpr std::size_t kMediumItemBytes = 4096U;
inline constexpr std::size_t kLargeItemBytes = 16384U;

// type, version, address, class, lifetime: the bytes of a DEPOSIT body before
// its sealed bytes.
inline constexpr std::size_t kDepositHeadBytes = 1U + 2U + 32U + 1U + 4U;
// The longest body a client may send: a DEPOSIT of the largest size.
inline constexpr std::uint32_t kMaxRequestBody =
    kDepositHeadBytes + kLargeItemBytes;
static_assert(kMaxRequestBody == 16424U);
inline constexpr std::size_t kMaxRequestFrameBytes =
    kFrameLengthBytes + kMaxRequestBody;

// Length, type, class, address, item ID, deposit minute, seconds left.
inline constexpr std::size_t kItemHeadBytes =
    kFrameLengthBytes + 1U + 1U + 32U + kItemIdBytes + 4U + 4U;
inline constexpr std::size_t kMaxItemFrameBytes =
    kItemHeadBytes + kLargeItemBytes;
static_assert(kMaxItemFrameBytes - kFrameLengthBytes == 16442U);

inline constexpr std::size_t kMaxOpenedFrameBytes =
    kFrameLengthBytes + 1U + kMaxSecretsPerOpen;
inline constexpr std::size_t kStatusFrameBytes = kFrameLengthBytes + 2U;
inline constexpr std::size_t kDepositedFrameBytes =
    kFrameLengthBytes + 1U + kItemIdBytes + 4U;
inline constexpr std::size_t kSignalFrameBytes = kFrameLengthBytes + 1U;

enum class FrameType : std::uint8_t {
    Open = 1,
    Opened = 2,
    Item = 3,
    Taken = 4,
    Close = 5,
    Closed = 6,
    Deposit = 7,
    Deposited = 8,
    Rejected = 9,
    Ping = 10,
    Pong = 11,
    Refused = 12,
};

enum class ItemClass : std::uint8_t {
    Message = 1,
    Ring = 2,
};

// The status space OPENED, CLOSED and REJECTED share.
enum class Status : std::uint8_t {
    Done = 1,
    // OPEN: the principal holds its inboxes. DEPOSIT: unknown, ended or full.
    NotHere = 2,
    Later = 3,
};

enum class RefusalReason : std::uint8_t {
    UnsupportedProtocol = 2,
    Capacity = 3,
    Timeout = 5,
    InvalidRequest = 6,
};
// Refusal counts are indexed by reason - 1.
inline constexpr std::size_t kRefusalReasons = 6U;

// Whether size is one of the three item sizes.
[[nodiscard]] constexpr bool valid_item_size(std::size_t size) noexcept {
    return size == kSmallItemBytes || size == kMediumItemBytes ||
           size == kLargeItemBytes;
}

struct OpenRequest final {
    // 1 to 512 secrets of 32 bytes, back to back.
    std::span<const std::byte> secrets;
    [[nodiscard]] std::size_t count() const noexcept {
        return secrets.size() / kSecretBytes;
    }
    [[nodiscard]] Secret secret(std::size_t index) const noexcept;
};

struct TakenRequest final {
    // 1 to 512 item IDs of 16 bytes, back to back.
    std::span<const std::byte> ids;
    [[nodiscard]] std::size_t count() const noexcept {
        return ids.size() / kItemIdBytes;
    }
    [[nodiscard]] ItemId id(std::size_t index) const noexcept;
};

struct CloseRequest final {
    std::span<const std::byte> secret_bytes;
    [[nodiscard]] Secret secret() const noexcept;
};

struct DepositRequest final {
    Address address{};
    ItemClass item_class{ItemClass::Message};
    // At least one second.
    std::uint32_t lifetime_seconds{0U};
    // 1024, 4096 or 16384 bytes.
    std::span<const std::byte> sealed;
};

struct PingRequest final {};

using Request = std::variant<OpenRequest, TakenRequest, CloseRequest,
                             DepositRequest, PingRequest>;

enum class RequestStatus {
    Incomplete,
    Decoded,
    // A length outside 1..16424, an unknown or service-only type, a wrong
    // payload size or an out-of-range field.
    Invalid,
    // An OPEN, CLOSE or DEPOSIT whose version field is not 1.
    Unsupported,
};

struct RequestParse final {
    RequestStatus status{RequestStatus::Incomplete};
    std::size_t consumed{0U};
    Request request{PingRequest{}};
};

// Decodes one client request from the start of input. A length outside the
// version-1 bounds is Invalid as soon as its four bytes are present, before
// any body is buffered.
[[nodiscard]] RequestParse parse_request(
    std::span<const std::byte> input) noexcept;

// Encoders write one whole frame to the start of out, which must hold it, and
// return its size.
std::size_t encode_opened(std::span<const Status> statuses,
                          std::span<std::byte> out) noexcept;
std::size_t encode_status(FrameType type, Status status,
                          std::span<std::byte> out) noexcept;
std::size_t encode_deposited(const ItemId& id, std::uint32_t granted_seconds,
                             std::span<std::byte> out) noexcept;
std::size_t encode_signal(FrameType type, std::span<std::byte> out) noexcept;
std::size_t encode_refused(RefusalReason reason,
                           std::span<std::byte> out) noexcept;

struct ItemHead final {
    ItemClass item_class{ItemClass::Message};
    Address address{};
    ItemId id{};
    std::uint32_t deposit_minute{0U};
    std::uint32_t seconds_left{0U};
    std::size_t sealed_bytes{0U};
};

// Writes an ITEM's first kItemHeadBytes. Its sealed bytes follow.
void encode_item_head(const ItemHead& head,
                      std::span<std::byte, kItemHeadBytes> out) noexcept;

}  // namespace ito::mailbox
