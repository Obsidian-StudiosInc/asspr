#  This file is part of asspr.
#
#  asspr is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  asspr is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with asspr.  If not, see <http://www.gnu.org/licenses/>.

cmake_minimum_required (VERSION 2.6)
enable_testing()
project (asspr C)
set(VERSION_MAJOR 0)
set(VERSION_MINOR 2)
set(VERSION_PATCH 9)
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

configure_file ("${PROJECT_SOURCE_DIR}/src/config.h.in"
                "${PROJECT_SOURCE_DIR}/src/config.h" )

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -g -fprofile-arcs -ftest-coverage")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall")

IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
ENDIF()

set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fprofile-arcs -ftest-coverage")
set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS}")

set(CMAKE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/dist)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_OUTPUT_DIRECTORY})

set(CMAKE_INSTALL_PREFIX "/")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

# Compile
add_executable(asspr src/asspr.c src/main.c)

IF (${CMAKE_BUILD_TYPE} MATCHES "Debug")
	find_package(Check REQUIRED)
	find_package(Threads REQUIRED)

	add_executable(asspr-test EXCLUDE_FROM_ALL tests/asspr-test.c src/asspr.c)
	target_link_libraries(asspr-test check pthread)
	add_test(asspr-test ${CMAKE_OUTPUT_DIRECTORY}/asspr-test)
ENDIF()

# Install
install(TARGETS asspr RUNTIME DESTINATION usr/bin)
install(FILES ${PROJECT_SOURCE_DIR}/asspr.8
	DESTINATION usr/share/man/man8)

# Package Sources
set(CPACK_SOURCE_GENERATOR "TBZ2")
set(CPACK_SOURCE_IGNORE_FILES
"${PROJECT_SOURCE_DIR}/.git/"
"${PROJECT_SOURCE_DIR}/.gitignore"
"${PROJECT_SOURCE_DIR}/CMakeCache.txt"
"${PROJECT_SOURCE_DIR}/CMakeFiles"
"${PROJECT_SOURCE_DIR}/_CPack_Packages/"
"${PROJECT_SOURCE_DIR}/CPackConfig.cmake"
"${PROJECT_SOURCE_DIR}/CPackSourceConfig.cmake"
"${PROJECT_SOURCE_DIR}/build"
"${PROJECT_SOURCE_DIR}/cmake_install.cmake"
"${PROJECT_SOURCE_DIR}/nbproject/"
"${PROJECT_SOURCE_DIR}/dist/"
"${PROJECT_SOURCE_DIR}/docs/"
"${PROJECT_SOURCE_DIR}/install_manifest.txt"
)

# Create RPM
set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_GENERATOR "DEB;RPM;TBZ2")
set(CPACK_PACKAGE_NAME "asspr")
set(CPACK_PACKAGE_CONTACT "William L. Thomson Jr.")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "William L. Thomson Jr.")
set(CPACK_PACKAGE_VENDOR "Obsidian-Studios, Inc.")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}.${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_OUTPUT_FILE_PREFIX dist)
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/COPYING")
set(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/README.md")
include(CPack)
