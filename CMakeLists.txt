cmake_minimum_required(VERSION 3.22)
project(file_defender LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Export compile_commands.json so the clangd VS Code extension gives accurate
# IntelliSense. clangd automatically looks in the build/ directory.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# nlohmann/json for parsing the exported model. Prefer the system package
# (sudo apt install nlohmann-json3-dev); fall back to downloading it.
find_package(nlohmann_json 3.2.0 QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# --- Collector: fanotify (the primary, capable collector) ---
add_executable(fanotify_collector src/collector/fanotify_collector.c)
target_compile_options(fanotify_collector PRIVATE -Wall -Wextra)
target_link_libraries(fanotify_collector PRIVATE m)  # log2() lives in libm

# --- Collector: inotify (a small teaching comparison) ---
add_executable(inotify_demo src/collector/inotify_demo.c)
target_compile_options(inotify_demo PRIVATE -Wall -Wextra)

# --- Daemon: consumes events, scores them, alerts ---
add_executable(file_defender_daemon
    src/daemon/main.cpp
    src/daemon/feature_window.cpp
    src/daemon/anomaly_model.cpp
)
target_include_directories(file_defender_daemon PRIVATE src/common src/daemon)
target_compile_options(file_defender_daemon PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(file_defender_daemon PRIVATE nlohmann_json::nlohmann_json)
