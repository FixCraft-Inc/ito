# Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later.
#
# The mailbox is a host service, separate from the Android application and
# its Gradle build. It links only the C++ standard library.

cmake_minimum_required(VERSION 3.25)
project(ito_mailbox VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "ito-mailbox uses epoll, signalfd and SO_PEERCRED and builds on Linux only")
endif()

option(ITO_MAILBOX_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
set(ITO_MAILBOX_SANITIZE "" CACHE STRING "Sanitizers for every target, such as address,undefined")
option(ITO_MAILBOX_TESTS "Build and register the mailbox tests" ON)

find_package(Threads REQUIRED)

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
                    -Wnon-virtual-dtor -Wold-style-cast -fstack-protector-strong)
if(ITO_MAILBOX_WARNINGS_AS_ERRORS)
    add_compile_options(-Werror)
endif()
if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT ITO_MAILBOX_SANITIZE)
    add_compile_definitions(_FORTIFY_SOURCE=3)
endif()
add_link_options(-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
if(ITO_MAILBOX_SANITIZE)
    add_compile_options(-fsanitize=${ITO_MAILBOX_SANITIZE} -fno-omit-frame-pointer
                        -fno-sanitize-recover=all)
    add_link_options(-fsanitize=${ITO_MAILBOX_SANITIZE})
endif()

# The module header, the listener trust boundary and the startup checks every
# Ito module shares, built with the options above.
set(ITO_MODULE_TESTS ${ITO_MAILBOX_TESTS})
if(ITO_MAILBOX_TESTS)
    enable_testing()
endif()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../module ${CMAKE_CURRENT_BINARY_DIR}/module)

# Parsing, the store, the policy table, the storage worker and the event
# loop. The program and the tests link the same objects.
add_library(ito_mailbox_core STATIC
    src/mailbox.cpp
    src/mailbox_table.cpp
    src/sha256.cpp
    src/storage_worker.cpp
    src/store.cpp
    src/wire.cpp)
target_include_directories(ito_mailbox_core PUBLIC src)
target_link_libraries(ito_mailbox_core PUBLIC ito_module Threads::Threads)

add_executable(ito-mailbox src/main.cpp)
target_link_libraries(ito-mailbox PRIVATE ito_mailbox_core)
set_target_properties(ito-mailbox PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_options(ito-mailbox PRIVATE -pie)

if(ITO_MAILBOX_TESTS)
    find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)
    foreach(_ito_mailbox_test IN ITEMS sha256 wire store table loop)
        add_executable(ito_mailbox_${_ito_mailbox_test}_test
                       tests/${_ito_mailbox_test}_test.cpp)
        target_include_directories(ito_mailbox_${_ito_mailbox_test}_test
                                   PRIVATE ../module/tests)
        target_link_libraries(ito_mailbox_${_ito_mailbox_test}_test
                              PRIVATE ito_mailbox_core)
        add_test(NAME ito_mailbox_${_ito_mailbox_test}_test
                 COMMAND ito_mailbox_${_ito_mailbox_test}_test)
    endforeach()
    # The full-disk case needs unprivileged user namespaces, and reports 77
    # when the host forbids them.
    set_tests_properties(ito_mailbox_store_test PROPERTIES SKIP_RETURN_CODE 77)
    # The real program against synthetic module peers, with the version-1
    # default limits. -B keeps bytecode out of the source tree.
    add_test(NAME ito_mailbox_component_test
             COMMAND Python3::Interpreter -B
                     ${CMAKE_CURRENT_SOURCE_DIR}/tests/component_test.py
                     --mailbox $<TARGET_FILE:ito-mailbox>)
    set_tests_properties(ito_mailbox_component_test PROPERTIES TIMEOUT 600)
endif()
