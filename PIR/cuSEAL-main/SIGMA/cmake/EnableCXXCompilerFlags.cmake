# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

include(CheckCXXCompilerFlag)

# For easier adding of CXX compiler flags
function(sigma_enable_cxx_compiler_flag_if_supported flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        message(STATUS "Adding CXX compiler flag: ${flag} ...")
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()

if(NOT MSVC AND SIGMA_DEBUG)
    sigma_enable_cxx_compiler_flag_if_supported("-Wall")
    sigma_enable_cxx_compiler_flag_if_supported("-Wextra")
    sigma_enable_cxx_compiler_flag_if_supported("-Wconversion")
    sigma_enable_cxx_compiler_flag_if_supported("-Wshadow")
    sigma_enable_cxx_compiler_flag_if_supported("-pedantic")
endif()
