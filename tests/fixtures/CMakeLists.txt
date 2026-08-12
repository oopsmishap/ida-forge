cmake_minimum_required(VERSION 3.20)
project(ida_forge_fixtures C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

add_executable(pure_c_struct_fixture
  c_pure_structs/src/fixture.c
  c_pure_structs/src/main.c)
target_include_directories(pure_c_struct_fixture PRIVATE c_pure_structs/include)

add_executable(complex_fixture
  cpp_complex/src/fixture.cpp
  cpp_complex/src/main.cpp)
target_include_directories(complex_fixture PRIVATE cpp_complex/include)

# NOTE: the old `complex_fixture_debug` target existed to work around a
# duplicate `run_demo` definition in fixture.cpp. That duplicate is fixed, so
# the debug variant is no longer needed.
