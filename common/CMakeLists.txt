cmake_minimum_required (VERSION 3.5)

add_library(${PROJECT_NAME}-common OBJECT
    list.c
    md5.c
    aarch64/debug.S
    aarch64/ticket.c
    aarch64/misc.S
)
