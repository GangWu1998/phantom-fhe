cmake_minimum_required(VERSION 3.20)

project(Phantom 
    LANGUAGES CXX CUDA 
    VERSION 2.0 
    DESCRIPTION "CUDA-Accelerated Homomorphic Encryption Library"
)

# Options
option(PHANTOM_USE_CUDA_PTX "Use CUDA PTX Assembly" ON)
if (PHANTOM_USE_CUDA_PTX)
    add_compile_definitions(PHANTOM_USE_CUDA_PTX)
endif ()

# CUDA settings
if (NOT DEFINED CMAKE_CUDA_ARCHITECTURES)
    set(CMAKE_CUDA_ARCHITECTURES native)
endif ()
set(CMAKE_CUDA_SEPARABLE_COMPILATION ON)

# C++ and CUDA standards
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)

# Global settings
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

# NTL and GMP settings
set(NTL_INCLUDE_DIR "/usr/local/include")
set(NTL_LIBRARY "/usr/local/lib/libntl.a")

set(GMP_INCLUDE_DIR "/usr/local/include")
set(GMP_LIBRARY "/usr/local/lib/libgmpxx.a")
set(GMPXX_LIBRARY "/usr/local/lib/libgmp.a")

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include ${NTL_INCLUDE_DIR} ${GMP_INCLUDE_DIR})

# Find all source files for Phantom
file(GLOB_RECURSE PHANTOM_SOURCES "src/*.cu")

# Main Phantom library
add_library(Phantom STATIC ${PHANTOM_SOURCES})

target_compile_options(Phantom PRIVATE 
    "$<$<AND:$<CONFIG:Debug>,$<COMPILE_LANGUAGE:CUDA>>:-G;-src-in-ptx>"
)
target_compile_features(Phantom PUBLIC cxx_std_17 cuda_std_17)
target_link_libraries(Phantom PRIVATE ${NTL_LIBRARY} ${GMP_LIBRARY} ${GMPXX_LIBRARY})

# Find all source files for Boot
file(GLOB_RECURSE BOOT_SOURCES "bootstrapping/*.cu")

# Bootstrapping library
add_library(Boot STATIC ${BOOT_SOURCES})

target_compile_options(Boot PRIVATE 
    "$<$<AND:$<CONFIG:Debug>,$<COMPILE_LANGUAGE:CUDA>>:-G;-bootstrapping-in-ptx>"
)
target_compile_features(Boot PUBLIC cxx_std_17 cuda_std_17)
target_link_libraries(Boot PRIVATE Phantom ${NTL_LIBRARY} ${GMP_LIBRARY} ${GMPXX_LIBRARY})

# Installation
install(TARGETS Phantom Boot
    EXPORT PhantomConfig
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)
install(EXPORT PhantomConfig 
    NAMESPACE phantom:: 
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/phantom
)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ 
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/phantom
)


# Google Test setup
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)
# Enable testing
enable_testing()

# Add the tests subdirectory
add_subdirectory(tests)

add_subdirectory(examples)