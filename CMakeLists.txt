cmake_minimum_required(VERSION 3.10)
project(SecureFileGuard CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
if(NOT MSVC)
  add_compile_options(-Wall -Wextra)
endif()

find_package(Threads REQUIRED)

add_library(guard STATIC
  src/guard_v0.cpp src/guard_v1.cpp src/guard_v2.cpp src/guard_v3.cpp src/guard_v4.cpp)
target_include_directories(guard PUBLIC src)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
  target_link_libraries(guard PUBLIC stdc++fs)
endif()

add_executable(guard_cli cli/guard_cli.cpp)
target_link_libraries(guard_cli guard)

add_executable(run_tests tests/run_tests.cpp tests/test_cases.cpp)
target_link_libraries(run_tests guard)

add_executable(toctou_race demo/toctou_race.cpp)
target_link_libraries(toctou_race guard Threads::Threads)
