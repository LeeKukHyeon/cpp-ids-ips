cmake_minimum_required(VERSION 3.15)
project(cpp_ids_ips)

set(CMAKE_CXX_STANDARD 17)
include_directories(include)
file(GLOB SOURCES "src/*.cpp")

add_executable(cpp-ids-ips ${SOURCES})

# OS별 링크 설정
if(WIN32)
    target_compile_definitions(cpp-ids-ips PRIVATE PLATFORM_WINDOWS)
    target_link_libraries(cpp-ids-ips ws2_32)
elseif(UNIX)
    target_compile_definitions(cpp-ids-ips PRIVATE PLATFORM_LINUX)
endif()