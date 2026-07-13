cmake_minimum_required(VERSION 3.15)
project(symbridge_x64dbg CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Path to the x64dbg plugin SDK (the "pluginsdk" folder from an x64dbg snapshot).
# Pass with:  cmake -DX64DBG_SDK="C:/path/to/pluginsdk" ...
if(NOT DEFINED X64DBG_SDK)
    message(FATAL_ERROR "Set -DX64DBG_SDK=<path to pluginsdk>")
endif()

add_library(symbridge SHARED symbridge_x64dbg.cpp pluginmain.h type_sync.h)

target_include_directories(symbridge PRIVATE
    "${X64DBG_SDK}"
    "${X64DBG_SDK}/jansson")

# x64 build. For a 32-bit x64dbg use x32dbg.lib / x32bridge.lib / jansson_x86.lib
# and a .dp32 suffix instead.
target_link_libraries(symbridge PRIVATE
    "${X64DBG_SDK}/x64dbg.lib"
    "${X64DBG_SDK}/x64bridge.lib"
    "${X64DBG_SDK}/jansson/jansson_x64.lib"
    ws2_32)

set_target_properties(symbridge PROPERTIES
    OUTPUT_NAME "symbridge"
    PREFIX ""
    SUFFIX ".dp64")
