cmake_minimum_required(VERSION 3.23)
project(https_server)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 14)

set(SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Server.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Socket.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
)

add_executable(https_server src/main.cpp)

include_directories(https_server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_library(https STATIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Server.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/Socket.cpp
)

target_link_libraries(https_server
        PRIVATE
            OpenSSL::SSL
            https
)