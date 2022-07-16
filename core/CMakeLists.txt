cmake_minimum_required (VERSION 3.5)

add_library(${PROJECT_NAME}-core OBJECT
    core_entrypoint.S
    main.c
    guest-entry.S
    guest-dispatcher.S
    crash_reporting.S
)
