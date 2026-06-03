cmake_minimum_required(VERSION 3.16)

project(VulpineToolchain LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Validation: Ensure we are not building for 32-bit (x86)
# This prevents the -4 Architecture Mismatch error at runtime
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "VDE Error: This project must be compiled for x64. "
                        "Please change your CMake Kit/Generator to x64 (amd64).")
endif()

# Add both the root directory and the src directory to the include path
# This ensures VS Code IntelliSense can resolve headers no matter where they sit
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Define the executable target using the main file inside src
add_executable(VXE
    src/main.cpp
    src/VDE.cpp
)

# Explicitly bind the include targets to the executable for the compiler
target_include_directories(VXE PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)