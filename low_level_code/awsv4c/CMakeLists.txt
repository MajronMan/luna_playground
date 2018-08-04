cmake_minimum_required(VERSION 3.10)
project(awsv4c C)

set(CMAKE_C_STANDARD 90)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Werror")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY 
${CMAKE_SOURCE_DIR}/Awsv4sig/native_libs/linux)

add_library(awsv4sig SHARED src/main.c src/StrLen/StrLen.c src/StrLen/StrLen.h src/Hash/Hash.c src/Hash/Hash.h)
target_link_libraries(awsv4sig crypto)
