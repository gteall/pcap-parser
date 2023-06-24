cmake_minimum_required(VERSION 3.1)

project(pcap-parser)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set (CMAKE_CXX_STANDARD 14)

include_directories("cmdline")
add_executable(pcap-parser  pcap_parser.cpp)
