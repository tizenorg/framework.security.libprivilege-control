#Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


# @file        CMakeLists.txt
# @author      Jan Olszak (j.olszak@samsung.com)
# @version     0.1
# @brief       CMake file for the api_feature_loader

SET(TARGET_API_FEATURE_LOADER "api_feature_loader")

#dependencies
PKG_CHECK_MODULES(TARGET_DEP
    libsmack
    REQUIRED
    )

#files to compile
SET(TARGET_SOURCES
    ${PROJECT_SOURCE_DIR}/api_feature_loader/api_feature_loader.c
    ${PROJECT_SOURCE_DIR}/src/common.c
    ${PROJECT_SOURCE_DIR}/src/privilege-control.c
    ${PROJECT_SOURCE_DIR}/src/rules-db.c
    ${PROJECT_SOURCE_DIR}/src/rules-db-internals.c
    )

SET_SOURCE_FILES_PROPERTIES(
    ${TARGET_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-fPIE")

#header directories
INCLUDE_DIRECTORIES(
    ${TARGET_DEP_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/include
    )

#output format
ADD_EXECUTABLE(${TARGET_API_FEATURE_LOADER} ${TARGET_SOURCES})

#linker directories
TARGET_LINK_LIBRARIES(${TARGET_API_FEATURE_LOADER}
    ${TARGET_DEP_LIBRARIES}
    ${TARGET_PRIVILEGE_CONTROL}
    -pie
    )

#place for output file
INSTALL(TARGETS ${TARGET_API_FEATURE_LOADER}
    DESTINATION /usr/bin
    PERMISSIONS
    OWNER_READ
    OWNER_WRITE
    OWNER_EXECUTE
    )
