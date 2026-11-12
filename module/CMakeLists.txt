# Copyright (C) 2026 FixCraft Inc. AGPL-3.0-or-later.
#
# What every Ito YUME module shares: the module header grammar, the listener
# trust checks and the startup plumbing. A module project adds this directory
# with add_subdirectory after setting its compile options, so the library is
# built with the same warnings and sanitizers as the module itself. Set
# ITO_MODULE_TESTS before adding it to register the grammar test.

add_library(ito_module STATIC
    src/listener.cpp
    src/module_header.cpp
    src/process.cpp)
target_include_directories(ito_module PUBLIC src)

if(ITO_MODULE_TESTS)
    add_executable(ito_module_test tests/module_test.cpp)
    target_include_directories(ito_module_test PRIVATE tests)
    target_link_libraries(ito_module_test PRIVATE ito_module)
    add_test(NAME ito_module_test COMMAND ito_module_test)
endif()
