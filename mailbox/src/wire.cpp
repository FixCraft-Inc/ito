/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "wire.hpp"

#include <algorithm>

namespace ito::mailbox {
namespace {

std::uint16_t read_u16(std::span<const std::byte> bytes) noexcept {
    return static_cast<std::uint16_t>(
        (std::to_integer<unsigned>(bytes[0]) << 8U) |
        std::to_integer<unsigned>(bytes[1]));
}

std::uint32_t read_u32(std::span<const std::byte> bytes) noexcept {
    return (std::to_integer<std::uint32_t>(bytes[0]) << 24U) |
           (std::to_integer<std::uint32_t>(bytes[1]) << 16U) |
           (std::to_integer<std::uint32_t>(bytes[2]) << 8U) |
           std::to_integer<std::uint32_t>(bytes[3]);
}

std::byte* put_u32(std::byte* out, std::uint32_t value) noexcept {
    out[0] = static_cast<std::byte>(value >> 24U);
    out[1] = static_cast<std::byte>(value >> 16U);
    out[2] = static_cast<std::byte>(value >> 8U);
    out[3] = static_cast<std::byte>(value);
    return out + 4;
}

template <std::size_t N>
std::array<std::uint8_t, N> copy_field(
    std::span<const std::byte> from) noexcept {
    std::array<std::uint8_t, N> to{};
    std::transform(
        from.begin(), from.begin() + N, to.begin(),
        [](std::byte byte) { return std::to_integer<std::uint8_t>(byte); });
    return to;
}

template <std::size_t N>
std::byte* put_field(std::byte* out,
                     const std::array<std::uint8_t, N>& field) noexcept {
    return std::transform(field.begin(), field.end(), out,
                          [](std::uint8_t byte) { return std::byte{byte}; });
}

// Starts a frame whose body, type included, is body_bytes long.
std::byte* begin_frame(std::span<std::byte> out, FrameType type,
                       std::size_t body_bytes) noexcept {
    std::byte* cursor =
        put_u32(out.data(), static_cast<std::uint32_t>(body_bytes));
    *cursor = std::byte{static_cast<std::uint8_t>(type)};
    return cursor + 1;
}

RequestParse invalid() noexcept {
    return {RequestStatus::Invalid, 0U, PingRequest{}};
}

// OPEN, CLOSE and DEPOSIT start with their version. A version other than 1
// is unsupported whatever its length, so a later version can change the
// payload.
bool unsupported_version(std::span<const std::byte> payload) noexcept {
    return payload.size() >= 2U && read_u16(payload) != kProtocolVersion;
}

}  // namespace

Secret OpenRequest::secret(std::size_t index) const noexcept {
    return copy_field<kSecretBytes>(
        secrets.subspan(index * kSecretBytes, kSecretBytes));
}

ItemId TakenRequest::id(std::size_t index) const noexcept {
    return copy_field<kItemIdBytes>(
        ids.subspan(index * kItemIdBytes, kItemIdBytes));
}

Secret CloseRequest::secret() const noexcept {
    return copy_field<kSecretBytes>(secret_bytes);
}

RequestParse parse_request(std::span<const std::byte> input) noexcept {
    if (input.size() < kFrameLengthBytes) return {};
    const std::uint32_t body = read_u32(input);
    if (body == 0U || body > kMaxRequestBody) return invalid();
    if (input.size() - kFrameLengthBytes < body) return {};
    const auto type = std::to_integer<std::uint8_t>(input[kFrameLengthBytes]);
    const auto payload = input.subspan(kFrameLengthBytes + 1U, body - 1U);
    const std::size_t consumed = kFrameLengthBytes + body;
    switch (type) {
        case static_cast<std::uint8_t>(FrameType::Open): {
            if (unsupported_version(payload))
                return {RequestStatus::Unsupported, 0U, PingRequest{}};
            if (payload.size() < 2U) return invalid();
            const auto secrets = payload.subspan(2U);
            if (secrets.empty() || secrets.size() % kSecretBytes != 0U ||
                secrets.size() / kSecretBytes > kMaxSecretsPerOpen)
                return invalid();
            return {RequestStatus::Decoded, consumed, OpenRequest{secrets}};
        }
        case static_cast<std::uint8_t>(FrameType::Taken): {
            if (payload.empty() || payload.size() % kItemIdBytes != 0U ||
                payload.size() / kItemIdBytes > kMaxIdsPerTaken)
                return invalid();
            return {RequestStatus::Decoded, consumed, TakenRequest{payload}};
        }
        case static_cast<std::uint8_t>(FrameType::Close): {
            if (unsupported_version(payload))
                return {RequestStatus::Unsupported, 0U, PingRequest{}};
            if (payload.size() != 2U + kSecretBytes) return invalid();
            return {RequestStatus::Decoded, consumed,
                    CloseRequest{payload.subspan(2U)}};
        }
        case static_cast<std::uint8_t>(FrameType::Deposit): {
            if (unsupported_version(payload))
                return {RequestStatus::Unsupported, 0U, PingRequest{}};
            constexpr std::size_t head = kDepositHeadBytes - 1U;
            if (payload.size() < head ||
                !valid_item_size(payload.size() - head))
                return invalid();
            DepositRequest deposit;
            deposit.address = copy_field<32U>(payload.subspan(2U, 32U));
            const auto item_class = std::to_integer<std::uint8_t>(payload[34]);
            if (item_class != static_cast<std::uint8_t>(ItemClass::Message) &&
                item_class != static_cast<std::uint8_t>(ItemClass::Ring))
                return invalid();
            deposit.item_class = static_cast<ItemClass>(item_class);
            deposit.lifetime_seconds = read_u32(payload.subspan(35U, 4U));
            if (deposit.lifetime_seconds == 0U) return invalid();
            deposit.sealed = payload.subspan(head);
            return {RequestStatus::Decoded, consumed, deposit};
        }
        case static_cast<std::uint8_t>(FrameType::Ping):
            if (!payload.empty()) return invalid();
            return {RequestStatus::Decoded, consumed, PingRequest{}};
        default:
            // Unknown types and the service's own frame types.
            return invalid();
    }
}

std::size_t encode_opened(std::span<const Status> statuses,
                          std::span<std::byte> out) noexcept {
    std::byte* cursor =
        begin_frame(out, FrameType::Opened, 1U + statuses.size());
    for (const Status status : statuses)
        *cursor++ = std::byte{static_cast<std::uint8_t>(status)};
    return static_cast<std::size_t>(cursor - out.data());
}

std::size_t encode_status(FrameType type, Status status,
                          std::span<std::byte> out) noexcept {
    std::byte* cursor = begin_frame(out, type, 2U);
    *cursor = std::byte{static_cast<std::uint8_t>(status)};
    return kStatusFrameBytes;
}

std::size_t encode_deposited(const ItemId& id, std::uint32_t granted_seconds,
                             std::span<std::byte> out) noexcept {
    std::byte* cursor =
        begin_frame(out, FrameType::Deposited, 1U + kItemIdBytes + 4U);
    put_u32(put_field(cursor, id), granted_seconds);
    return kDepositedFrameBytes;
}

std::size_t encode_signal(FrameType type, std::span<std::byte> out) noexcept {
    begin_frame(out, type, 1U);
    return kSignalFrameBytes;
}

std::size_t encode_refused(RefusalReason reason,
                           std::span<std::byte> out) noexcept {
    std::byte* cursor = begin_frame(out, FrameType::Refused, 2U);
    *cursor = std::byte{static_cast<std::uint8_t>(reason)};
    return kStatusFrameBytes;
}

void encode_item_head(const ItemHead& head,
                      std::span<std::byte, kItemHeadBytes> out) noexcept {
    std::byte* cursor =
        begin_frame(out, FrameType::Item,
                    kItemHeadBytes - kFrameLengthBytes + head.sealed_bytes);
    *cursor++ = std::byte{static_cast<std::uint8_t>(head.item_class)};
    cursor = put_field(cursor, head.address);
    cursor = put_field(cursor, head.id);
    cursor = put_u32(cursor, head.deposit_minute);
    put_u32(cursor, head.seconds_left);
}

}  // namespace ito::mailbox
