cmake_minimum_required(VERSION 3.14)
project(retracing-boomerang)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)

# Disable in-source builds
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

# Include headers
include_directories(${CMAKE_SOURCE_DIR}/include)

# Add sources
add_subdirectory(${CMAKE_SOURCE_DIR}/src)

enable_testing()
add_subdirectory(${CMAKE_SOURCE_DIR}/tests)
