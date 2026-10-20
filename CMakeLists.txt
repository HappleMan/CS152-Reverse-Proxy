cmake_minimum_required(VERSION 3.20)
project(CS152_Reverse_Proxy C)

set(CMAKE_C_STANDARD 11)

add_executable(CS152_Reverse_Proxy
        server.c
        reverseProxy.cpp)
