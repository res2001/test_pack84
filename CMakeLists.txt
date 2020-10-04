cmake_minimum_required(VERSION 3.7.0)
project(pack84 CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

add_executable(pack84 pack84.cpp portable_endian.h)
