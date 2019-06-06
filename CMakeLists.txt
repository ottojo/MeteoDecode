cmake_minimum_required(VERSION 3.14)
project(MeteoDecode C)

set(CMAKE_C_STANDARD 11)

add_library(MeteoDecode meteo.c)

add_executable(test test.c)
target_link_libraries(test MeteoDecode)