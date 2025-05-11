# Get all sources
file(GLOB TEST_SOURCES *.cpp)

foreach(TEST_SOURCE ${TEST_SOURCES})
    # Get the filename without the extension
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)

    # Add the test executable
    add_executable(${TEST_NAME} ${TEST_SOURCE})

    # Link against the main library
    target_link_libraries(${TEST_NAME} ${CMAKE_PROJECT_NAME})

    # Add the test to CTest
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()