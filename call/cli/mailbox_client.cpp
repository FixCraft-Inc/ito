/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "mailbox_client.hpp"

#include <algorithm>
#include <chrono>
#include <string>

namespace ito::cli {
namespace {

// Frame types of docs/MAILBOX.md.
constexpr std::uint8_t kOpen = 1U;
constexpr std::uint8_t kOpened = 2U;
constexpr std::uint8_t kItem = 3U;
constexpr std::uint8_t kTaken = 4U;
constexpr std::uint8_t kDeposit = 7U;
constexpr std::uint8_t kDeposited = 8U;
constexpr std::uint8_t kRejected = 9U;
constexpr std::uint8_t kRefused = 12U;

constexpr std::uint16_t kVersion = 1U;
// The longest body the service sends: an ITEM with a 16384-byte item.
constexpr std::uint32_t kMaxBody = 16442U;
// Class, address, ID, deposit minute and seconds left.
constexpr std::size_t kItemFixed = 1U + 32U + 16U + 4U + 4U;
constexpr std::size_t kMaxIds = 512U;
// A frame that began must finish in this long, and a reply must begin.
constexpr std::uint32_t kFrameBudgetMs = 5000U;
constexpr std::uint32_t kReplyBudgetMs = 20000U;

void put16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8U));
    out.push_back(static_cast<std::uint8_t>(value));
}

void put32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    put16(out, static_cast<std::uint16_t>(value >> 16U));
    put16(out, static_cast<std::uint16_t>(value));
}

[[nodiscard]] std::uint32_t get32(const std::uint8_t* in) noexcept {
    return (std::uint32_t{in[0]} << 24U) | (std::uint32_t{in[1]} << 16U) |
           (std::uint32_t{in[2]} << 8U) | std::uint32_t{in[3]};
}

}  // namespace

void MailboxClient::write_frame(std::uint8_t type,
                                const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> frame;
    frame.reserve(5U + payload.size());
    put32(frame, static_cast<std::uint32_t>(1U + payload.size()));
    frame.push_back(type);
    frame.insert(frame.end(), payload.begin(), payload.end());
    if (transport_.write(transport_.user_data, frame.data(), frame.size(),
                         kFrameBudgetMs) != ITO_IO_OK) {
        throw MailboxError("the mailbox stream did not take a frame");
    }
}

bool MailboxClient::read_exact(std::uint8_t* out, std::size_t size,
                               std::uint32_t timeout_ms, bool idle) {
    using Clock = std::chrono::steady_clock;
    std::size_t done = 0U;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    while (done < size) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - Clock::now());
        if (left.count() <= 0) {
            if (idle && done == 0U) return false;
            throw MailboxError("the mailbox stream stalled inside a frame");
        }
        std::size_t received = 0U;
        const int32_t status = transport_.read(
            transport_.user_data, out + done, size - done, &received,
            static_cast<std::uint32_t>(left.count()));
        if (status == ITO_IO_TIMEOUT) continue;
        if (status != ITO_IO_OK || received == 0U) {
            throw MailboxError("the mailbox stream ended");
        }
        if (done == 0U && idle) {
            // A frame began: the rest has its own budget.
            deadline = Clock::now() + std::chrono::milliseconds(kFrameBudgetMs);
        }
        done += received;
    }
    return true;
}

std::optional<MailboxClient::Frame> MailboxClient::read_frame(
    std::uint32_t timeout_ms) {
    std::array<std::uint8_t, 4> length{};
    if (!read_exact(length.data(), length.size(), timeout_ms, true)) {
        return std::nullopt;
    }
    const std::uint32_t body = get32(length.data());
    if (body == 0U || body > kMaxBody) {
        throw MailboxError("the mailbox sent a frame of a wrong length");
    }
    Frame frame;
    std::vector<std::uint8_t> bytes(body);
    (void)read_exact(bytes.data(), bytes.size(), kFrameBudgetMs, false);
    frame.type = bytes[0];
    frame.payload.assign(bytes.begin() + 1, bytes.end());
    if (frame.type == kRefused) {
        throw MailboxError(
            "the mailbox refused the stream, reason " +
            std::to_string(frame.payload.empty() ? 0U : frame.payload[0]));
    }
    return frame;
}

MailboxItem MailboxClient::parse_item(const Frame& frame) {
    if (frame.payload.size() < kItemFixed) {
        throw MailboxError("the mailbox sent a malformed item");
    }
    const std::size_t sealed = frame.payload.size() - kItemFixed;
    if (sealed != 1024U && sealed != 4096U && sealed != 16384U) {
        throw MailboxError("the mailbox sent a malformed item");
    }
    const std::uint8_t* in = frame.payload.data();
    MailboxItem item;
    item.item_class = in[0];
    std::copy_n(in + 1, 32U, item.address.begin());
    std::copy_n(in + 33, 16U, item.id.begin());
    item.deposit_minute = get32(in + 49);
    item.seconds_left = get32(in + 53);
    item.sealed.assign(in + kItemFixed, in + frame.payload.size());
    return item;
}

MailboxClient::Frame MailboxClient::reply(std::uint8_t type) {
    for (;;) {
        std::optional<Frame> frame = read_frame(kReplyBudgetMs);
        if (!frame) throw MailboxError("the mailbox did not answer");
        if (frame->type == kItem) {
            pushed_.push_back(parse_item(*frame));
            continue;
        }
        if (frame->type == kRejected && type == kDeposited) {
            throw MailboxError("the mailbox rejected the deposit, status " +
                               std::to_string(frame->payload.empty()
                                                  ? 0U
                                                  : frame->payload[0]));
        }
        if (frame->type != type) {
            throw MailboxError("the mailbox answered out of order");
        }
        return std::move(*frame);
    }
}

std::vector<std::uint8_t> MailboxClient::open(
    const std::vector<InboxSecret>& secrets) {
    if (secrets.empty() || secrets.size() > kMaxIds) {
        throw MailboxError("an OPEN names 1 to 512 inboxes");
    }
    std::vector<std::uint8_t> payload;
    payload.reserve(2U + secrets.size() * 32U);
    put16(payload, kVersion);
    for (const InboxSecret& secret : secrets) {
        payload.insert(payload.end(), secret.begin(), secret.end());
    }
    write_frame(kOpen, payload);
    std::fill(payload.begin(), payload.end(), std::uint8_t{0U});
    Frame opened = reply(kOpened);
    if (opened.payload.size() != secrets.size()) {
        throw MailboxError("the mailbox answered OPEN with the wrong count");
    }
    return opened.payload;
}

std::uint32_t MailboxClient::deposit(const MailboxAddress& address,
                                     std::uint8_t item_class,
                                     std::uint32_t lifetime,
                                     const std::uint8_t* sealed,
                                     std::size_t size) {
    std::vector<std::uint8_t> payload;
    payload.reserve(2U + 32U + 1U + 4U + size);
    put16(payload, kVersion);
    payload.insert(payload.end(), address.begin(), address.end());
    payload.push_back(item_class);
    put32(payload, lifetime);
    payload.insert(payload.end(), sealed, sealed + size);
    write_frame(kDeposit, payload);
    const Frame deposited = reply(kDeposited);
    if (deposited.payload.size() != 16U + 4U) {
        throw MailboxError("the mailbox sent a malformed DEPOSITED");
    }
    return get32(deposited.payload.data() + 16);
}

void MailboxClient::taken(const std::vector<ItemId>& ids) {
    for (std::size_t first = 0U; first < ids.size(); first += kMaxIds) {
        std::vector<std::uint8_t> payload;
        const std::size_t last = std::min(ids.size(), first + kMaxIds);
        for (std::size_t index = first; index < last; ++index) {
            payload.insert(payload.end(), ids[index].begin(), ids[index].end());
        }
        write_frame(kTaken, payload);
    }
}

std::optional<MailboxItem> MailboxClient::next_item(std::uint32_t timeout_ms) {
    if (!pushed_.empty()) {
        MailboxItem item = std::move(pushed_.front());
        pushed_.pop_front();
        return item;
    }
    std::optional<Frame> frame = read_frame(timeout_ms);
    if (!frame) return std::nullopt;
    if (frame->type != kItem) {
        throw MailboxError("the mailbox sent an unexpected frame");
    }
    return parse_item(*frame);
}

}  // namespace ito::cli
