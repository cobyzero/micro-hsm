cmake_minimum_required(VERSION 3.31.4)
project(demo_MultiThreading VERSION 1.0.0 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake_modules")

find_package(PKCS11 REQUIRED)
find_package(Threads REQUIRED)

add_executable(demo_MultiThreading)
target_sources(demo_MultiThreading
        PRIVATE
        FILE_SET headers
        TYPE HEADERS
        BASE_DIRS include
        FILES include/demo_MultiThreading.h)
target_sources(demo_MultiThreading
        PRIVATE
        src/demo_MultiThreading.cpp
        src/example_ops.cpp)

target_link_libraries(demo_MultiThreading PRIVATE PKCS11::PKCS11 Threads::Threads ${CMAKE_DL_LIBS})
