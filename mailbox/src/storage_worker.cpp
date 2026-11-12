/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

#include "storage_worker.hpp"

#include <sys/eventfd.h>
#include <unistd.h>

#include <cstring>
#include <new>
#include <system_error>
#include <utility>

namespace ito::mailbox {

std::unique_ptr<StorageWorker> StorageWorker::start(const Store& store) {
    module::Descriptor wake(::eventfd(0U, EFD_NONBLOCK | EFD_CLOEXEC));
    if (wake.get() < 0) return nullptr;
    try {
        std::unique_ptr<StorageWorker> worker(
            new StorageWorker(store, std::move(wake)));
        worker->thread_ = std::thread([raw = worker.get()] { raw->run(); });
        return worker;
    } catch (const std::bad_alloc&) {
        return nullptr;
    } catch (const std::system_error&) {
        return nullptr;
    }
}

StorageWorker::StorageWorker(const Store& store,
                             module::Descriptor wake) noexcept
    : store_(store), wake_(std::move(wake)) {}

StorageWorker::~StorageWorker() {
    {
        const std::lock_guard lock(mutex_);
        stopping_ = true;
    }
    work_ready_.notify_one();
    if (thread_.joinable()) thread_.join();
}

std::uint64_t StorageWorker::submit(std::unique_ptr<Job> job) {
    std::uint64_t sequence = 0U;
    {
        const std::lock_guard lock(mutex_);
        // The worker returns every job without allocating, because the
        // finished list always has room for each job not yet taken back.
        if (finished_.capacity() < outstanding_ + 1U)
            finished_.reserve(2U * (outstanding_ + 1U));
        sequence = next_sequence_;
        job->sequence = sequence;
        pending_.push_back(std::move(job));
        ++next_sequence_;
    }
    ++outstanding_;
    work_ready_.notify_one();
    return sequence;
}

void StorageWorker::take_finished(std::vector<std::unique_ptr<Job>>& out) {
    std::uint64_t drained = 0U;
    [[maybe_unused]] const auto read =
        ::read(wake_.get(), &drained, sizeof drained);
    out.reserve(out.size() + outstanding_);
    const std::lock_guard lock(mutex_);
    for (auto& job : finished_) out.push_back(std::move(job));
    outstanding_ -= finished_.size();
    finished_.clear();
}

void StorageWorker::run() noexcept {
    for (;;) {
        std::unique_ptr<Job> job;
        {
            std::unique_lock lock(mutex_);
            work_ready_.wait(lock,
                             [this] { return stopping_ || !pending_.empty(); });
            if (pending_.empty()) return;
            job = std::move(pending_.front());
            pending_.pop_front();
        }
        execute(*job);
        {
            const std::lock_guard lock(mutex_);
            // submit() reserved this room.
            finished_.push_back(std::move(job));
        }
        const std::uint64_t one = 1U;
        [[maybe_unused]] const auto written =
            ::write(wake_.get(), &one, sizeof one);
    }
}

void StorageWorker::execute(Job& job) const noexcept {
    switch (job.kind) {
        case Job::Kind::CreateInbox:
            job.result = store_.create_inbox(job.address, job.day);
            return;
        case Job::Kind::RenewRegistration:
            job.result = store_.renew_registration(job.address, job.day);
            return;
        case Job::Kind::WriteMessage:
            job.result = store_.write_message(
                job.address, job.message,
                std::span<const std::byte>(job.sealed.get(), job.sealed_bytes));
            // The bytes are on disk or refused. The job keeps no copy.
            ::explicit_bzero(job.sealed.get(), job.sealed_bytes);
            job.sealed.reset();
            return;
        case Job::Kind::DeleteMessage:
            job.result = store_.delete_message(job.address, job.message);
            return;
        case Job::Kind::CloseInbox:
            job.result = store_.close_inbox(job.address);
            return;
        case Job::Kind::Barrier:
            job.result = IoResult::Ok;
            return;
    }
}

}  // namespace ito::mailbox
