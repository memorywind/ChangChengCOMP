# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Remove native/src/gsl directory which is no longer used in version >= 3.5.0
if(EXISTS ${SIGMA_INCLUDES_DIR}/gsl)
    message(STATUS "Removing ${SIGMA_INCLUDES_DIR}/gsl; this is no longer used by Microsoft SIGMA >= 3.5.0")
    file(REMOVE_RECURSE ${SIGMA_INCLUDES_DIR}/gsl)
endif()

# Remove thirdparty/zlib/src/CMakeCache.txt: the location changed in SIGMA >= 3.5.4
if(EXISTS ${SIGMA_THIRDPARTY_DIR}/zlib/src/CMakeCache.txt)
    message(STATUS "Removing old ${SIGMA_THIRDPARTY_DIR}/zlib/src/CMakeCache.txt")
    file(REMOVE ${SIGMA_THIRDPARTY_DIR}/zlib/src/CMakeCache.txt)
endif()

# Remove config.h from source tree
if(EXISTS ${SIGMA_INCLUDES_DIR}/sigma/util/config.h)
    message(STATUS "Removing old ${SIGMA_INCLUDES_DIR}/sigma/util/config.h")
    file(REMOVE ${SIGMA_INCLUDES_DIR}/sigma/util/config.h)
endif()
