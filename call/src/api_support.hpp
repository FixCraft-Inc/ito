/* Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later. */

// What the two halves of the C interface share: ito/call.h's api.cpp and
// ito/message.h's message_api.cpp implement one library over the same
// context and store handles, status mapping and exception containment.

#pragma once

#include <ito/call.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>

#include "codec.hpp"
#include "crypto.hpp"
#include "status.hpp"
#include "store.hpp"

struct ito_context {
    ito::call::CryptoContext crypto;
    std::atomic<std::size_t> stores{0U};
};

struct ito_store {
    ito_context* context{nullptr};
    std::unique_ptr<ito::call::Store> store;
};

namespace ito::call::api {

// Set while a platform callback (persistence or transport) runs on this
// thread. The core refuses to be reentered from one.
inline thread_local bool in_callback = false;

class CallbackScope final {
public:
    CallbackScope() noexcept { in_callback = true; }
    CallbackScope(const CallbackScope&) = delete;
    CallbackScope& operator=(const CallbackScope&) = delete;
    ~CallbackScope() { in_callback = false; }
};

// Each core status maps to exactly one ito_status.
[[nodiscard]] ito_status to_c(Status status) noexcept;

// Runs body and turns any escaped exception into a status. Every exported
// function goes through here, so none can throw across the interface.
template <class Body>
ito_status contained(Body&& body) noexcept {
    if (in_callback) return ITO_STATUS_REENTRANT;
    try {
        return body();
    } catch (const std::bad_alloc&) {
        return ITO_STATUS_OUT_OF_MEMORY;
    } catch (const CryptoFailure&) {
        return ITO_STATUS_DEPENDENCY_FAILURE;
    } catch (...) {
        return ITO_STATUS_INTERNAL;
    }
}

template <class T>
[[nodiscard]] bool sized(const T* value) noexcept {
    return value != nullptr && value->struct_size >= sizeof(T);
}

[[nodiscard]] inline Key key_of(const uint8_t* bytes) noexcept {
    Key key{};
    std::copy_n(bytes, key.size(), key.begin());
    return key;
}

// A caller's authority, refused unless its service is a valid name.
[[nodiscard]] bool authority_of(const ito_authority* source,
                                Authority& authority);

}  // namespace ito::call::api
