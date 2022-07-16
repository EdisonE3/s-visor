cmake_minimum_required (VERSION 3.5)

add_library(${PROJECT_NAME}-lib OBJECT
    libc/printf.c
    libc/putchar.c
    libc/puts.c
)
