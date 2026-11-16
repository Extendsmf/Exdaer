cmake_minimum_required(VERSION 3.20)
project(exdaer_agent CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
include_directories(
    includes
    src
)
set(AGENT_SOURCES
    src/agent.cpp
    src/telemetry.pb.cc
    src/telemetry.grpc.pb.cc
)

if(WIN32)
    list(APPEND AGENT_SOURCES src/windows_collector.cpp)
elseif(UNIX)
    list(APPEND AGENT_SOURCES src/linux_collector.cpp)
endif()

add_executable(agent ${AGENT_SOURCES})

target_link_libraries(agent PRIVATE
    protobuf::libprotobuf
    gRPC::grpc++
)

if(WIN32)
    target_link_libraries(agent PRIVATE wevtapi)
endif()

