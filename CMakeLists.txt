cmake_minimum_required (VERSION 2.6)

project (MCProxy)

include(SetFlags.cmake)
set_flags()
set_lib_flags()

add_subdirectory(lib/zlib/)

include(lib/polarssl.cmake)

set_exe_flags()

add_subdirectory (src)

