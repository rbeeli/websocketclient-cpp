cmake_minimum_required(VERSION 3.21)

project(websocketclient_consumer LANGUAGES CXX)

find_package(websocketclient 0.7.4 CONFIG REQUIRED)

add_executable(websocketclient_consumer main.cpp)
target_link_libraries(websocketclient_consumer PRIVATE websocketclient::websocketclient)
