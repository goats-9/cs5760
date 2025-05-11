# Collect sources
file(GLOB_RECURSE SOURCES *.cpp)

# Required packages
pkg_check_modules(M4RI REQUIRED m4ri)
pkg_check_modules(M4RIE REQUIRED m4rie)

# Add as library
add_library(${CMAKE_PROJECT_NAME} STATIC ${SOURCES})
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Include headers
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${M4RI_INCLUDE_DIRS})
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE ${M4RI_CFLAGS_OTHER})
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE ${M4RI_LIBRARY_DIRS})
target_link_libraries(${CMAKE_PROJECT_NAME} ${M4RI_LIBRARIES})

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${M4RIE_INCLUDE_DIRS})
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE ${M4RIE_CFLAGS_OTHER})
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE ${M4RIE_LIBRARY_DIRS})
target_link_libraries(${CMAKE_PROJECT_NAME} ${M4RIE_LIBRARIES})