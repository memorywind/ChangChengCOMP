# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check for intrin.h or x86intrin.h
if(SIGMA_USE_INTRIN)
    set(CMAKE_REQUIRED_QUIET_OLD ${CMAKE_REQUIRED_QUIET})
    set(CMAKE_REQUIRED_QUIET ON)

    if(MSVC)
        set(SIGMA_INTRIN_HEADER "intrin.h")
    else()
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
            set(SIGMA_ARM64 ON)
        else()
            set(SIGMA_ARM64 OFF)
        endif()
        if(SIGMA_ARM64)
            set(SIGMA_INTRIN_HEADER "arm_neon.h")
        elseif(EMSCRIPTEN)
            set(SIGMA_INTRIN_HEADER "wasm_simd128.h")
        else()
            set(SIGMA_INTRIN_HEADER "x86intrin.h")
        endif()
    endif()

    check_include_file_cxx(${SIGMA_INTRIN_HEADER} SIGMA_INTRIN_HEADER_FOUND)
    set(CMAKE_REQUIRED_QUIET ${CMAKE_REQUIRED_QUIET_OLD})

    if(SIGMA_INTRIN_HEADER_FOUND)
        message(STATUS "${SIGMA_INTRIN_HEADER} - found")
    else()
        message(STATUS "${SIGMA_INTRIN_HEADER} - not found")
    endif()
endif()
