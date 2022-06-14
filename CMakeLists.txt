cmake_minimum_required(VERSION 3.23)
project(https_server)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")

set(SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
)

add_executable(https_server src/main.cpp)

include_directories(https_server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_library(https STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/server.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/message.cpp
)

target_link_libraries(https_server
        PRIVATE
            OpenSSL::SSL
            https
)