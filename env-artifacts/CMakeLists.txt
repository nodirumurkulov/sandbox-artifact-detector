cmake_minimum_required(VERSION 3.15)
project(detector VERSION 1.1.0 LANGUAGES C)

# set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# collect sources (includes cpuid_check.c on all platforms)
file(GLOB SOURCES "src/*.c")

add_executable(detector ${SOURCES})

# VMware backdoor probe: MASM helper required because MSVC x64 has no inline __asm.
# ml64.exe (part of every VS installation) assembles the .asm file.
if (WIN32 AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    enable_language(ASM_MASM)
    target_sources(detector PRIVATE src/vmware_backdoor_asm.asm)
endif()

# Include headers
include_directories(include)

# Windows-specific linker: iphlpapi used later for MAC enumeration, COM/WMI for BIOS
if (WIN32)
  target_link_libraries(detector PRIVATE iphlpapi wbemuuid ole32 oleaut32 Psapi Advapi32 Shlwapi Shell32)
endif()

# installation (optional)
install(TARGETS detector DESTINATION bin)

