cmake_minimum_required(VERSION 3.14 FATAL_ERROR)
project(pico_bench LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

message("CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")

# Make Release by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if (NOT CMAKE_BINARY_DIR OR ${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    set(CMAKE_BINARY_DIR "${CMAKE_SOURCE_DIR}/build")
endif()
set(CMAKE_CACHEFILE_DIR ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib" CACHE PATH "Path to static libs")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib" CACHE PATH "Path to shared libs")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmax-errors=1")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
endif()

include(cmake/picotls.cmake)
include(cmake/libressl.cmake)

add_executable(pico_openssl servers/pico_openssl.cpp)
target_link_libraries(pico_openssl picotls-core picotls-openssl crypto)

add_executable(pico_minicrypto servers/pico_minicrypto.cpp)
target_link_libraries(pico_minicrypto picotls-core picotls-minicrypto crypto)

add_executable(open_ssl servers/open.cpp)
target_link_libraries(open_ssl ssl crypto)

add_executable(libre_ssl servers/libre.cpp)
target_link_libraries(libre_ssl PRIVATE libressl::tls )

