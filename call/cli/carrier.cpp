/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "carrier.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>

#include "stub_mailbox.hpp"
#include "yume_transport.hpp"

namespace ito::cli {
namespace {

// A message's longest hold time. The service grants its own hold time.
constexpr std::uint32_t kRequestedLifetime = 30U * 24U * 60U * 60U;
// Collecting ends when no item arrived for this long after the OPEN.
constexpr std::uint32_t kQuietMs = 1500U;
constexpr std::uint32_t kOpenTimeoutMs = 30000U;

MailboxTarget target_of(const ito_mailbox_target& target) {
    MailboxTarget result;
    std::copy_n(target.server_fingerprint, ITO_KEY_BYTES,
                result.server.begin());
    result.service.assign(target.service, target.service_size);
    std::copy_n(target.address, ITO_MAILBOX_ADDRESS_BYTES,
                result.address.begin());
    return result;
}

class StubCarrier final : public Carrier {
public:
    explicit StubCarrier(const std::string& directory) : stub_(directory) {}

    std::uint32_t deposit(const ito_mailbox_target& target,
                          const std::uint8_t* item, std::size_t size,
                          bool ring) override {
        if (ring)
            throw std::runtime_error(
                "rings need the in-memory mailbox service");
        stub_.deposit(target_of(target), item, size);
        return 0U;
    }

    // The stub keeps no registrations.
    void open(const std::vector<ito_inbox>&) override {}

    std::vector<WaitingItem> collect(const std::vector<ito_inbox>& inboxes,
                                     bool) override {
        std::vector<WaitingItem> result;
        for (std::size_t index = 0U; index < inboxes.size(); ++index) {
            for (StubItem& item :
                 stub_.waiting(target_of(inboxes[index].mailbox))) {
                WaitingItem waiting;
                waiting.inbox = index;
                waiting.name = std::move(item.name);
                waiting.bytes = std::move(item.bytes);
                result.push_back(std::move(waiting));
            }
        }
        return result;
    }

    void take(const std::vector<ito_inbox>& inboxes,
              const WaitingItem& item) override {
        stub_.take(target_of(inboxes[item.inbox].mailbox), item.name);
    }

    const ito_authority* authority() const noexcept override { return nullptr; }

private:
    StubMailbox stub_;
};

class ServiceCarrier final : public Carrier {
public:
    ServiceCarrier(const std::string& config_dir, const std::string& resolver,
                   const std::string& service)
        : stream_(config_dir, resolver, service, kOpenTimeoutMs),
          transport_(stream_.transport()),
          client_(transport_) {}

    std::uint32_t deposit(const ito_mailbox_target& target,
                          const std::uint8_t* item, std::size_t size,
                          bool ring) override {
        // Another relay needs its own connection, which comes later.
        if (!here(target)) {
            throw std::runtime_error("the item's mailbox is on another relay");
        }
        MailboxAddress address{};
        std::copy_n(target.address, address.size(), address.begin());
        return client_.deposit(
            address, ring ? 2U : kMessageClass,
            ring ? ITO_RING_HOLD_SECONDS : kRequestedLifetime, item, size);
    }

    void open(const std::vector<ito_inbox>& inboxes) override {
        std::vector<std::size_t> fresh;
        for (std::size_t index = 0U; index < inboxes.size(); ++index) {
            if (here(inboxes[index].mailbox) &&
                opened_.count(address_of(inboxes[index])) == 0U) {
                fresh.push_back(index);
            }
        }
        open_indexes(inboxes, fresh);
    }

    std::vector<WaitingItem> collect(const std::vector<ito_inbox>& inboxes,
                                     bool restart) override {
        // Ordinary collects replay untaken items. A ringing wait keeps its
        // subscription so polling cannot exhaust the OPEN quota.
        std::vector<std::size_t> listed;
        std::map<MailboxAddress, std::size_t> wanted;
        for (std::size_t index = 0U; index < inboxes.size(); ++index) {
            if (!here(inboxes[index].mailbox)) continue;
            listed.push_back(index);
            wanted.emplace(address_of(inboxes[index]), index);
        }
        std::vector<WaitingItem> result;
        if (listed.empty()) return result;
        if (restart)
            open_indexes(inboxes, listed);
        else
            open(inboxes);
        while (std::optional<MailboxItem> item = client_.next_item(kQuietMs)) {
            const auto found = wanted.find(item->address);
            if (found == wanted.end()) continue;
            WaitingItem waiting;
            waiting.inbox = found->second;
            waiting.id = item->id;
            waiting.bytes = std::move(item->sealed);
            result.push_back(std::move(waiting));
        }
        return result;
    }

    void take(const std::vector<ito_inbox>&, const WaitingItem& item) override {
        client_.taken({item.id});
    }

    const ito_authority* authority() const noexcept override {
        return &stream_.authority();
    }

private:
    [[nodiscard]] static MailboxAddress address_of(const ito_inbox& inbox) {
        MailboxAddress address{};
        std::copy_n(inbox.mailbox.address, address.size(), address.begin());
        return address;
    }

    // One OPEN for the inboxes at these indexes. Every one must open.
    void open_indexes(const std::vector<ito_inbox>& inboxes,
                      const std::vector<std::size_t>& indexes) {
        if (indexes.empty()) return;
        std::vector<InboxSecret> secrets(indexes.size());
        for (std::size_t slot = 0U; slot < indexes.size(); ++slot) {
            std::copy_n(inboxes[indexes[slot]].secret, secrets[slot].size(),
                        secrets[slot].begin());
        }
        std::vector<std::uint8_t> statuses;
        try {
            statuses = client_.open(secrets);
        } catch (...) {
            for (InboxSecret& secret : secrets) secret.fill(0U);
            throw;
        }
        for (InboxSecret& secret : secrets) secret.fill(0U);
        if (std::any_of(
                statuses.begin(), statuses.end(),
                [](std::uint8_t status) { return status != kStatusDone; })) {
            throw std::runtime_error("the mailbox did not open every inbox");
        }
        for (const std::size_t index : indexes) {
            opened_.insert(address_of(inboxes[index]));
        }
    }

    [[nodiscard]] bool here(const ito_mailbox_target& target) const {
        const ito_authority& own = stream_.authority();
        return target.service_size == own.service_size &&
               std::memcmp(target.service, own.service, own.service_size) ==
                   0 &&
               std::memcmp(target.server_fingerprint, own.server_fingerprint,
                           ITO_KEY_BYTES) == 0;
    }

    YumeStream stream_;
    ito_transport transport_;
    MailboxClient client_;
    // The inboxes this stream opened, which a later open skips.
    std::set<MailboxAddress> opened_;
};

}  // namespace

std::unique_ptr<Carrier> stub_carrier(const std::string& directory) {
    return std::make_unique<StubCarrier>(directory);
}

std::unique_ptr<Carrier> mailbox_carrier(const std::string& config_dir,
                                         const std::string& resolver,
                                         const std::string& service) {
    return std::make_unique<ServiceCarrier>(config_dir, resolver, service);
}

}  // namespace ito::cli
