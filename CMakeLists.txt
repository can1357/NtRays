cmake_minimum_required(VERSION 3.12)
project(NtRays)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Verify SDK paths
if(NOT EXISTS "${IDA_SDK_DIR}/include/ida.hpp")
    message(FATAL_ERROR "IDA SDK not found at ${IDA_SDK_DIR}. Please check your config.cmake file.")
endif()

if(NOT EXISTS "${HEXRAYS_SDK_DIR}/include/hexrays.hpp")
    message(FATAL_ERROR "Hexrays SDK not found at ${HEXRAYS_SDK_DIR}. Please check your config.cmake file.")
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/HexSuite
    ${IDA_SDK_DIR}/include
    ${HEXRAYS_SDK_DIR}/include
    ${CMAKE_SOURCE_DIR}/linux-pe/includes
)

# Add source files
set(SOURCES
    plugin.cpp
    nt_syscalls.cpp
)

# Create a shared library
add_library(NtRays SHARED ${SOURCES})

# Set output name
set_target_properties(NtRays PROPERTIES PREFIX "")
set_target_properties(NtRays PROPERTIES OUTPUT_NAME "NtRays64")

if(UNIX)
    set_target_properties(NtRays PROPERTIES SUFFIX ".so")
    if(APPLE)
        # macOS specific
        set_target_properties(NtRays PROPERTIES SUFFIX ".dylib")
    else()
        # Linux and other UNIX-based systems
        set_target_properties(NtRays PROPERTIES SUFFIX ".so")
    endif()
elseif(WIN32)
     set_target_properties(NtRays PROPERTIES SUFFIX ".dll")
endif()

# Link against IDA libraries
if(UNIX)
    if(APPLE)
        if(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
            # Ensure paths are correctly set
            message(STATUS "Linking for macOS ARM64")
            message(STATUS "IDA SDK directory: ${IDA_SDK_DIR}")

            target_link_directories(NtRays PRIVATE
                ${IDA_SDK_DIR}/lib/arm64_mac_clang_64
            )

            target_link_libraries(NtRays
                ida
                idalib
            )

            set_target_properties(NtRays PROPERTIES
                INSTALL_NAME_DIR "@rpath"
                BUILD_WITH_INSTALL_RPATH TRUE
                MACOSX_RPATH TRUE
            )

            target_link_options(NtRays PRIVATE
                -Wl,-rpath,@executable_path
                -Wl,-rpath,${IDA_SDK_DIR}/lib/arm64_mac_clang_64
            )

        elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
            # Linking for macOS x64
            message(STATUS "Linking for macOS x86_64")
            message(STATUS "IDA SDK directory: ${IDA_SDK_DIR}")

            target_link_directories(NtRays PRIVATE
                ${IDA_SDK_DIR}/lib/x64_mac_clang_64
            )

            target_link_libraries(NtRays
                ida
                idalib
            )

            set_target_properties(NtRays PROPERTIES
                INSTALL_NAME_DIR "@rpath"
                BUILD_WITH_INSTALL_RPATH TRUE
                MACOSX_RPATH TRUE
            )

            target_link_options(NtRays PRIVATE
                -Wl,-rpath,@executable_path
                -Wl,-rpath,${IDA_SDK_DIR}/lib/arm64_mac_clang_64
            )
        endif()

        # Suppress warnings for macOS (if needed)
        target_compile_options(NtRays PRIVATE -w)

    else() # Linux
        target_compile_options(NtRays PRIVATE -w)
        target_link_libraries(NtRays
            ${IDA_SDK_DIR}/lib/x64_linux_gcc_64/libida64.so
            ${IDA_SDK_DIR}/lib/x64_linux_gcc_64/pro.a
        )
    endif()
elseif(MSVC)
    target_link_libraries(NtRays
        ${IDA_SDK_DIR}/lib/x64_win_vc_64/ida
        ${IDA_SDK_DIR}/lib/x64_win_vc_64_s/pro
    )
endif()

# Suppress all warnings
if(MSVC)
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    target_compile_options(NtRays PRIVATE /W0)
else()
    target_compile_options(NtRays PRIVATE -w)
endif()