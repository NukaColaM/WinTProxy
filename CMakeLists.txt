cmake_minimum_required(VERSION 3.16)
project(WinTProxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wno-unknown-pragmas -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2 -DNDEBUG)
endif()

set(SOURCES
    src/app/main.c
    src/app/log.c
    src/app/config.c
    src/conntrack/conntrack.c
    src/process/lookup.c
    src/policy/rules.c
    src/dns/hijack.c
    src/dns/plan.c
    src/divert/adapter.c
    src/packet/context.c
    src/flow/action.c
    src/flow/executor.c
    src/flow/plan.c
    src/path/bypass.c
    src/path/classify.c
    src/path/proxy.c
    src/path/return.c
    src/relay/socks5.c
    src/relay/tcp.c
    src/relay/udp.c
    lib/cJSON/cJSON.c
)

add_executable(WinTProxy ${SOURCES})

target_compile_definitions(WinTProxy PRIVATE CJSON_HIDE_SYMBOLS)

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
install(FILES README.md LICENSE guide.md config.example.json DESTINATION share/WinTProxy)
