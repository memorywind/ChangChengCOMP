# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

set(SIGMA_USE_STD_BYTE OFF)
set(SIGMA_USE_SHARED_MUTEX OFF)
set(SIGMA_USE_IF_CONSTEXPR OFF)
set(SIGMA_USE_MAYBE_UNUSED OFF)
set(SIGMA_USE_NODISCARD OFF)
set(SIGMA_USE_STD_FOR_EACH_N OFF)
set(SIGMA_LANG_FLAG "-std=c++14")
if(SIGMA_USE_CXX17)
    set(SIGMA_USE_STD_BYTE ON)
    set(SIGMA_USE_SHARED_MUTEX ON)
    set(SIGMA_USE_IF_CONSTEXPR ON)
    set(SIGMA_USE_MAYBE_UNUSED ON)
    set(SIGMA_USE_NODISCARD ON)
    set(SIGMA_USE_STD_FOR_EACH_N ON)
    set(SIGMA_LANG_FLAG "-std=c++17")
endif()

# In some non-MSVC compilers std::for_each_n is not available even when compiling as C++17
if(SIGMA_USE_STD_FOR_EACH_N)
    cmake_push_check_state(RESET)
    set(CMAKE_REQUIRED_QUIET TRUE)

    if(NOT MSVC)
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O0 ${SIGMA_LANG_FLAG}")
        check_cxx_source_compiles("
            #include <algorithm>
            int main() {
                int a[1]{ 0 };
                volatile auto fun = std::for_each_n(a, 1, [](auto b) {});
                return 0;
            }"
            USE_STD_FOR_EACH_N
        )
        if(NOT USE_STD_FOR_EACH_N EQUAL 1)
            set(SIGMA_USE_STD_FOR_EACH_N OFF)
        endif()
        unset(USE_STD_FOR_EACH_N CACHE)
    endif()

    cmake_pop_check_state()
endif()
