cmake_minimum_required(VERSION 3.20)

project(CS152_Reverse_Proxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

add_executable(server server.c)
target_link_libraries(server PRIVATE Threads::Threads)

add_executable(reverseProxy reverseProxy.c)
target_link_libraries(reverseProxy PRIVATE Threads::Threads)