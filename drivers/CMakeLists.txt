cmake_minimum_required (VERSION 3.5)

add_library(${PROJECT_NAME}-driver OBJECT
    console/aarch64/console.S
    console/aarch64/deprecated_console.S
    arm/pl011/aarch64/pl011_console.S
)
