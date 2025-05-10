cmake_minimum_required(VERSION 3.14)
project(retracing-boomerang)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)

# Disable in-source builds
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

# Set debug flags
if (CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -g")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
endif()

# Include headers
include_directories(${CMAKE_SOURCE_DIR}/include)

# Add sources
add_subdirectory(${CMAKE_SOURCE_DIR}/src)

enable_testing()
add_subdirectory(${CMAKE_SOURCE_DIR}/tests)
