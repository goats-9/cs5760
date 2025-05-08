# Collect sources
file(GLOB_RECURSE SOURCES *.cpp)

# Add main.cpp as target executable
add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})

# Include headers
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Link m4ri
pkg_check_modules(M4RI REQUIRED m4ri)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${M4RI_INCLUDE_DIRS})
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE ${M4RI_CFLAGS_OTHER})
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE ${M4RI_LIBRARY_DIRS})
target_link_libraries(${CMAKE_PROJECT_NAME} ${M4RI_LIBRARIES})

# Add as library
add_library(${CMAKE_PROJECT_NAME}_LIB STATIC ${SOURCES})
target_include_directories(${CMAKE_PROJECT_NAME}_LIB PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(${CMAKE_PROJECT_NAME}_LIB ${M4RI_LIBRARIES})
