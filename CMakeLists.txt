cmake_minimum_required(VERSION 3.16)
project(WinTProxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wno-unknown-pragmas -DWIN32_LEAN_AND_MEAN)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2 -DNDEBUG)
endif()

set(SOURCES
    src/main.c
    src/log.c
    src/config.c
    src/connection.c
    src/process.c
    src/rules.c
    src/socks5.c
    src/dns.c
    src/divert.c
    src/tcp_relay.c
    src/udp_relay.c
    lib/cJSON/cJSON.c
)

add_executable(WinTProxy ${SOURCES})

target_include_directories(WinTProxy PRIVATE
    ${CMAKE_SOURCE_DIR}/inc
    ${CMAKE_SOURCE_DIR}/lib
)

target_link_libraries(WinTProxy PRIVATE
    ws2_32
    iphlpapi
    psapi
)

# WinDivert: link against MinGW import library.
# Generate it once from the .def file:
#   x86_64-w64-mingw32-dlltool -d lib/windivert/WinDivert.def -l lib/windivert/libWinDivert.a
# At runtime: place WinDivert.dll and WinDivert64.sys next to WinTProxy.exe
set(WINDIVERT_LIB_DIR "${CMAKE_SOURCE_DIR}/lib/windivert" CACHE PATH "Path to WinDivert import library")
if(EXISTS "${WINDIVERT_LIB_DIR}/libWinDivert.a")
    target_link_libraries(WinTProxy PRIVATE "${WINDIVERT_LIB_DIR}/libWinDivert.a")
else()
    message(WARNING "libWinDivert.a not found in ${WINDIVERT_LIB_DIR}. "
                    "Run: x86_64-w64-mingw32-dlltool -d ${WINDIVERT_LIB_DIR}/WinDivert.def -l ${WINDIVERT_LIB_DIR}/libWinDivert.a")
endif()

install(TARGETS WinTProxy RUNTIME DESTINATION bin)
