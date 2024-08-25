cmake_minimum_required(VERSION 3.5.0)
project(softhsm-practice VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

include_directories(include)

add_subdirectory(sample)

add_executable(softhsm-practice main.cpp)
target_link_libraries(softhsm-practice p11sample)
