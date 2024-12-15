cmake_minimum_required(VERSION 3.15)
project(mbedtlsplay C)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

find_package(MbedTLS REQUIRED)

add_executable(${PROJECT_NAME} src/main.c)
target_link_libraries(${PROJECT_NAME} MbedTLS::mbedtls)
