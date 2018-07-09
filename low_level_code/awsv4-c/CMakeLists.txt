cmake_minimum_required(VERSION 3.10)
project(awsv4_c C)

set(CMAKE_C_STANDARD 90)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Werror")


add_executable(awsv4_c
        main.c)
target_link_libraries(awsv4_c crypto curl)
