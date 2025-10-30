cmake_minimum_required(VERSION 3.10)
project(cpp-ids-ips)
set(CMAKE_CXX_STANDARD 17)


find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)


include_directories(${PCAP_INCLUDE_DIRS} src)


add_executable(${PROJECT_NAME}
src/main.cpp
src/capture/Capture.cpp
src/parser/Parser.cpp
src/rules/RuleLoader.cpp
src/rules/RuleEngine.cpp
src/alert/AlertManager.cpp
src/utils/Logger.cpp
)


target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARIES})