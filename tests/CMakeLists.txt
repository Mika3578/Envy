# CMakeLists.txt for Envy Tests
# Unit testing framework setup

cmake_minimum_required(VERSION 3.20)

# Only build tests if requested
option(BUILD_TESTS "Build test programs" OFF)

if(BUILD_TESTS)
    # Find or fetch Google Test
    include(FetchContent)

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
    )

    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    # Enable testing
    enable_testing()

    # Test executable template
    # Example: HashLib tests
    # add_executable(HashLibTests
    #     HashLib/test_md5.cpp
    #     HashLib/test_sha.cpp
    #     HashLib/test_ed2k.cpp
    # )
    # target_link_libraries(HashLibTests
    #     HashLib
    #     GTest::gtest
    #     GTest::gtest_main
    # )
    # add_test(NAME HashLibTests COMMAND HashLibTests)

    message(STATUS "Testing framework enabled (Google Test)")
    message(STATUS "  Add test executables in this directory")
else()
    message(STATUS "Testing framework disabled (set BUILD_TESTS=ON to enable)")
endif()
