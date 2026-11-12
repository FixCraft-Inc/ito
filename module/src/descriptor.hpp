/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// The one owner of a file descriptor. Closing it also removes it from any
// epoll set.

#pragma once

#include <unistd.h>

#include <utility>

namespace ito::module {

class Descriptor final {
public:
    Descriptor() noexcept = default;
    explicit Descriptor(int descriptor) noexcept : descriptor_(descriptor) {}
    Descriptor(Descriptor&& other) noexcept
        : descriptor_(std::exchange(other.descriptor_, -1)) {}
    Descriptor& operator=(Descriptor&& other) noexcept {
        if (this != &other) {
            reset();
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    ~Descriptor() { reset(); }

    [[nodiscard]] int get() const noexcept { return descriptor_; }
    void reset() noexcept {
        if (descriptor_ >= 0) ::close(descriptor_);
        descriptor_ = -1;
    }

private:
    int descriptor_{-1};
};

}  // namespace ito::module
