/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The thread that writes, syncs and deletes, so a slow disk never stalls the
// event loop. It runs jobs one at a time in submission order, which keeps the
// disk in the order the loop decided: a close submitted after a write always
// removes that write's file, and a creation submitted after a close always
// finds the old directory gone. Each finished job returns to the loop, which
// reads them after the completion descriptor becomes readable.

#pragma once

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "descriptor.hpp"
#include "store.hpp"
#include "wire.hpp"

namespace ito::mailbox {

using StreamId = std::uint64_t;

struct Job final {
    enum class Kind {
        CreateInbox,
        RenewRegistration,
        WriteMessage,
        DeleteMessage,
        CloseInbox,
        // Does nothing. Its completion means every earlier job completed.
        Barrier,
    };

    Kind kind{Kind::Barrier};
    Address address{};
    // CreateInbox and RenewRegistration: the registration's end day.
    std::uint32_t day{0U};
    MessageName message;
    // WriteMessage: the sealed bytes, which the job owns.
    std::unique_ptr<std::byte[]> sealed;
    std::size_t sealed_bytes{0U};
    // The registration the job belongs to, so a completion that arrives
    // after its inbox was closed changes nothing.
    std::uint64_t generation{0U};
    // The stream whose reply waits for this job, or 0.
    StreamId stream{0U};
    std::uint64_t sequence{0U};
    IoResult result{IoResult::Ok};
};

class StorageWorker final {
public:
    // Null when the thread or its descriptor cannot be created. store must
    // outlive the worker.
    [[nodiscard]] static std::unique_ptr<StorageWorker> start(
        const Store& store);
    // Finishes every submitted job, then joins the thread.
    ~StorageWorker();

    StorageWorker(const StorageWorker&) = delete;
    StorageWorker& operator=(const StorageWorker&) = delete;

    // Readable while finished jobs wait to be taken.
    [[nodiscard]] int completion_descriptor() const noexcept {
        return wake_.get();
    }
    // Assigns the job its sequence number and queues it. Throws bad_alloc
    // when the queues cannot grow, leaving the job unsubmitted.
    std::uint64_t submit(std::unique_ptr<Job> job);
    // Moves finished jobs, oldest first, into out. Throws bad_alloc, taking
    // nothing, when out cannot grow.
    void take_finished(std::vector<std::unique_ptr<Job>>& out);
    // Jobs submitted and not yet taken back.
    [[nodiscard]] std::size_t outstanding() const noexcept {
        return outstanding_;
    }

private:
    StorageWorker(const Store& store, module::Descriptor wake) noexcept;
    void run() noexcept;
    void execute(Job& job) const noexcept;

    const Store& store_;
    module::Descriptor wake_;
    std::mutex mutex_;
    std::condition_variable work_ready_;
    std::deque<std::unique_ptr<Job>> pending_;
    // Its capacity always covers every outstanding job.
    std::vector<std::unique_ptr<Job>> finished_;
    bool stopping_{false};
    std::uint64_t next_sequence_{1U};
    // Written by the loop's thread only, and read by it under the lock.
    std::size_t outstanding_{0U};
    std::thread thread_;
};

}  // namespace ito::mailbox
