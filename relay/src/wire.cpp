/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "wire.hpp"

#include <algorithm>

namespace ito::relay {
namespace {

constexpr std::size_t kReservePayloadBytes = 2U + 4U;
constexpr std::size_t kJoinPayloadBytes = 2U + 32U + 1U + 32U;

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

void write_u32(std::byte* out, std::uint32_t value) noexcept {
    out[0] = static_cast<std::byte>(value >> 24U);
    out[1] = static_cast<std::byte>(value >> 16U);
    out[2] = static_cast<std::byte>(value >> 8U);
    out[3] = static_cast<std::byte>(value);
}

template <std::size_t N>
void copy_field(std::span<const std::byte> from,
                std::array<std::uint8_t, N>& to) noexcept {
    std::transform(
        from.begin(), from.begin() + N, to.begin(),
        [](std::byte byte) { return std::to_integer<std::uint8_t>(byte); });
}

template <std::size_t N>
std::byte* put_field(std::byte* out,
                     const std::array<std::uint8_t, N>& field) noexcept {
    return std::transform(field.begin(), field.end(), out,
                          [](std::uint8_t byte) { return std::byte{byte}; });
}

RequestParse invalid() noexcept {
    return {RequestStatus::Invalid, 0U, {}};
}

// RESERVE and JOIN start with their version. A version other than 1 is
// unsupported whatever its length, so a later version can grow its payload.
bool unsupported_version(std::span<const std::byte> payload) noexcept {
    return payload.size() >= 2U && read_u16(payload) != kProtocolVersion;
}

}  // namespace

RequestParse parse_request(std::span<const std::byte> input) noexcept {
    if (input.size() < kFrameLengthBytes) return {};
    const std::uint32_t body = read_u32(input);
    if (body == 0U || body > kMaxFrameBody) return invalid();
    if (input.size() - kFrameLengthBytes < body) return {};
    const auto type = std::to_integer<std::uint8_t>(input[kFrameLengthBytes]);
    const auto payload = input.subspan(kFrameLengthBytes + 1U, body - 1U);
    const std::size_t consumed = kFrameLengthBytes + body;
    switch (type) {
        case static_cast<std::uint8_t>(FrameType::Reserve): {
            if (unsupported_version(payload))
                return {RequestStatus::Unsupported, 0U, {}};
            if (payload.size() != kReservePayloadBytes) return invalid();
            const std::uint32_t lifetime = read_u32(payload.subspan(2U));
            if (lifetime == 0U || lifetime > kMaxReservationMilliseconds)
                return invalid();
            return {RequestStatus::Decoded, consumed, ReserveRequest{lifetime}};
        }
        case static_cast<std::uint8_t>(FrameType::Join): {
            if (unsupported_version(payload))
                return {RequestStatus::Unsupported, 0U, {}};
            if (payload.size() != kJoinPayloadBytes) return invalid();
            const auto role = std::to_integer<std::uint8_t>(payload[34]);
            if (role != static_cast<std::uint8_t>(Role::Initiator) &&
                role != static_cast<std::uint8_t>(Role::Responder))
                return invalid();
            JoinRequest join;
            copy_field(payload.subspan(2U, 32U), join.room);
            join.role = static_cast<Role>(role);
            copy_field(payload.subspan(35U, 32U), join.token);
            return {RequestStatus::Decoded, consumed, join};
        }
        case static_cast<std::uint8_t>(FrameType::Cancel):
            if (!payload.empty()) return invalid();
            return {RequestStatus::Decoded, consumed, CancelRequest{}};
        default:
            // Unknown types and the service's own frame types.
            return invalid();
    }
}

ReservedFrame encode_reserved(const RoomId& room, const Token& initiator,
                              const Token& responder,
                              std::uint32_t lifetime_milliseconds) noexcept {
    ReservedFrame frame{};
    write_u32(frame.data(),
              static_cast<std::uint32_t>(frame.size() - kFrameLengthBytes));
    frame[kFrameLengthBytes] =
        std::byte{static_cast<std::uint8_t>(FrameType::Reserved)};
    auto* out = frame.data() + kFrameLengthBytes + 1U;
    out = put_field(out, room);
    out = put_field(out, initiator);
    out = put_field(out, responder);
    write_u32(out, lifetime_milliseconds);
    return frame;
}

SignalFrame encode_signal(FrameType type) noexcept {
    SignalFrame frame{};
    write_u32(frame.data(), 1U);
    frame[kFrameLengthBytes] = std::byte{static_cast<std::uint8_t>(type)};
    return frame;
}

RefusedFrame encode_refused(RefusalReason reason) noexcept {
    RefusedFrame frame{};
    write_u32(frame.data(), 2U);
    frame[kFrameLengthBytes] =
        std::byte{static_cast<std::uint8_t>(FrameType::Refused)};
    frame[kFrameLengthBytes + 1U] =
        std::byte{static_cast<std::uint8_t>(reason)};
    return frame;
}

}  // namespace ito::relay
