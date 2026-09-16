# CMakeLists.txt for Envy unit tests (auxiliary)
#
# Not a standalone app build. Prefer MSBuild `tests/EnvyTests.vcxproj` via
# Visual Studio/Envy.sln. This file exists for optional CMake-driven HashLib
# / test experiments when wired from a dedicated CMake entry point — there is
# no root CMakeLists that builds the Envy MFC client.

cmake_minimum_required(VERSION 3.20)

set(TEST_SOURCES
    test_main.cpp
    test_hashlib.cpp
)

set(TEST_HEADERS
    test_framework.h
)

add_executable(EnvyTests ${TEST_SOURCES} ${TEST_HEADERS})

target_include_directories(EnvyTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/HashLib
)

target_link_libraries(EnvyTests PRIVATE HashLib)

target_compile_features(EnvyTests PRIVATE cxx_std_17)

if(MSVC)
    target_compile_options(EnvyTests PRIVATE /W3 /EHsc)
endif()

add_test(NAME EnvyTests COMMAND EnvyTests)
