cmake_minimum_required(VERSION 3.16)
project(cpp-ids-ips)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)

find_package(PCRE2 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NFQ REQUIRED libnetfilter_queue)

include_directories(${NFQ_INCLUDE_DIRS})
include_directories(${PCRE2_INCLUDE_DIRS})
include_directories(src)

file(GLOB SOURCES
    src/main.cpp
    src/rules/*.cpp
    src/flow/*.cpp
    src/nfqueue/*.cpp
    src/logger/*.cpp
)

add_executable(cpp-ids-ips ${SOURCES})
target_link_libraries(cpp-ids-ips ${NFQ_LIBRARIES} ${PCRE2_LIBRARIES} pthread)
