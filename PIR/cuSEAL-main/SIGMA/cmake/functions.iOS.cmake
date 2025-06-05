# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# This cache-initialization file will be used to enable functions when cross-compiling
# for iOS, as check_cxx_source_runs fails for cross-compilers.

set(SIGMA_MEMSET_S_FOUND_EXITCODE
    "0"
    CACHE STRING "Result from TRY_RUN" FORCE)

set(SIGMA_MEMSET_S_FOUND_EXITCODE__TRYRUN_OUTPUT
    ""
    CACHE STRING "Output from TRY_RUN" FORCE)

set(SIGMA_ARM64_EXITCODE
    "0"
    CACHE STRING "Result from TRY_RUN" FORCE)

set (SIGMA_ARM64_EXITCODE__TRYRUN_OUTPUT
    ""
    CACHE STRING "Output from TRY_RUN" FORCE)

set(SIGMA___BUILTIN_CLZLL_FOUND_EXITCODE
    "0"
    CACHE STRING "Result from TRY_RUN" FORCE)

set(SIGMA___BUILTIN_CLZLL_FOUND_EXITCODE__TRYRUN_OUTPUT
    ""
    CACHE STRING "Output from TRY_RUN" FORCE)

set(SIGMA__ADDCARRY_U64_FOUND_EXITCODE
    "0"
    CACHE STRING "Result from TRY_RUN" FORCE)

set(SIGMA__ADDCARRY_U64_FOUND_EXITCODE__TRYRUN_OUTPUT
    ""
    CACHE STRING "Output from TRY_RUN" FORCE)

set(SIGMA__SUBBORROW_U64_FOUND_EXITCODE
    "0"
    CACHE STRING "Result from TRY_RUN" FORCE)

set(SIGMA__SUBBORROW_U64_FOUND_EXITCODE__TRYRUN_OUTPUT
    ""
    CACHE STRING "Output from TRY_RUN" FORCE)
