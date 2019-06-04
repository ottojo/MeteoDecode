cmake_minimum_required(VERSION 3.14)
project(MeteoDecode C)

set(CMAKE_C_STANDARD 11)

add_library(MeteoDecode meteo.c meteo.h secrets.h)
