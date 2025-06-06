# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Source files in this directory
set(SIGMA_SOURCE_FILES ${SIGMA_SOURCE_FILES}
        ${CMAKE_CURRENT_LIST_DIR}/blake2b.c
        ${CMAKE_CURRENT_LIST_DIR}/blake2xb.c
        ${CMAKE_CURRENT_LIST_DIR}/clipnormal.cpp
        ${CMAKE_CURRENT_LIST_DIR}/common.cpp
        ${CMAKE_CURRENT_LIST_DIR}/croots.cpp
        ${CMAKE_CURRENT_LIST_DIR}/fips202.c
        ${CMAKE_CURRENT_LIST_DIR}/globals.cpp
        ${CMAKE_CURRENT_LIST_DIR}/galois.cu
        ${CMAKE_CURRENT_LIST_DIR}/hash.cpp
        ${CMAKE_CURRENT_LIST_DIR}/iterator.cpp
        ${CMAKE_CURRENT_LIST_DIR}/mempool.cpp
        ${CMAKE_CURRENT_LIST_DIR}/numth.cpp
        ${CMAKE_CURRENT_LIST_DIR}/polyarithsmallmod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/rlwe.cpp
        ${CMAKE_CURRENT_LIST_DIR}/rns.cu
        ${CMAKE_CURRENT_LIST_DIR}/scalingvariant.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ntt.cpp
        ${CMAKE_CURRENT_LIST_DIR}/streambuf.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintarith.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintarithmod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintarithsmallmod.cpp
        ${CMAKE_CURRENT_LIST_DIR}/uintcore.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ztools.cpp
        ${CMAKE_CURRENT_LIST_DIR}/randomgenerator.cu
        ${CMAKE_CURRENT_LIST_DIR}/HostList.cu
)

# Add header files for installation
install(
        FILES
        ${CMAKE_CURRENT_LIST_DIR}/blake2.h
        ${CMAKE_CURRENT_LIST_DIR}/blake2-impl.h
        ${CMAKE_CURRENT_LIST_DIR}/clang.h
        ${CMAKE_CURRENT_LIST_DIR}/clipnormal.h
        ${CMAKE_CURRENT_LIST_DIR}/common.h
        ${CMAKE_CURRENT_LIST_DIR}/croots.h
        ${CMAKE_CURRENT_LIST_DIR}/defines.h
        ${CMAKE_CURRENT_LIST_DIR}/dwthandler.h
        ${CMAKE_CURRENT_LIST_DIR}/fips202.h
        ${CMAKE_CURRENT_LIST_DIR}/galois.h
        ${CMAKE_CURRENT_LIST_DIR}/gcc.h
        ${CMAKE_CURRENT_LIST_DIR}/globals.h
        ${CMAKE_CURRENT_LIST_DIR}/hash.h
        ${CMAKE_CURRENT_LIST_DIR}/hestdparms.h
        ${CMAKE_CURRENT_LIST_DIR}/iterator.h
        ${CMAKE_CURRENT_LIST_DIR}/locks.h
        ${CMAKE_CURRENT_LIST_DIR}/mempool.h
        ${CMAKE_CURRENT_LIST_DIR}/msvc.h
        ${CMAKE_CURRENT_LIST_DIR}/numth.h
        ${CMAKE_CURRENT_LIST_DIR}/pointer.h
        ${CMAKE_CURRENT_LIST_DIR}/polyarithsmallmod.h
        ${CMAKE_CURRENT_LIST_DIR}/polycore.h
        ${CMAKE_CURRENT_LIST_DIR}/rlwe.h
        ${CMAKE_CURRENT_LIST_DIR}/rns.cuh
        ${CMAKE_CURRENT_LIST_DIR}/scalingvariant.h
        ${CMAKE_CURRENT_LIST_DIR}/ntt.h
        ${CMAKE_CURRENT_LIST_DIR}/streambuf.h
        ${CMAKE_CURRENT_LIST_DIR}/uintarith.h
        ${CMAKE_CURRENT_LIST_DIR}/uintarithmod.h
        ${CMAKE_CURRENT_LIST_DIR}/uintarithsmallmod.h
        ${CMAKE_CURRENT_LIST_DIR}/uintcore.h
        ${CMAKE_CURRENT_LIST_DIR}/ztools.h
        ${CMAKE_CURRENT_LIST_DIR}/devicearray.cuh
        ${CMAKE_CURRENT_LIST_DIR}/hostarray.h
        ${CMAKE_CURRENT_LIST_DIR}/uint128_ntt.h
        ${CMAKE_CURRENT_LIST_DIR}/randomgenerator.cuh
        ${CMAKE_CURRENT_LIST_DIR}/HostList.h
        DESTINATION
        ${SIGMA_INCLUDES_INSTALL_DIR}/sigma/util
)

set(SIGMA_SOURCE_FILES ${SIGMA_SOURCE_FILES} PARENT_SCOPE)
