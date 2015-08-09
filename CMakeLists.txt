cmake_minimum_required(VERSION 2.8)
project(csocks)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -g3 -Wall")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -O2 -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_DEBUG}")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")

set(SOURCE_FILES src/main.cpp)
add_executable(csocks ${SOURCE_FILES} src/predef.hpp src/TcpRelay.cpp src/TcpRelay.hpp src/TcpRelayHandler.cpp src/TcpRelayHandler.hpp src/main.cpp src/Portal.cpp src/Portal.hpp src/Config.cpp src/Config.hpp src/Channel.cpp src/Channel.hpp src/Auth.cpp src/Authenticater.hpp src/Buffer.hpp src/Crypto.cpp src/Crypto.hpp)

include_directories( "../stage/ccpp" )

link_directories(/usr/lib/x86_64-linux-gnu)
target_link_libraries(csocks libboost_system.so libboost_filesystem.so )
