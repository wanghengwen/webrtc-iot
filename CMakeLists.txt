cmake_minimum_required(VERSION 3.1)

# Removed coreHTTP and coreMQTT dependencies - signaling handled by user application

if (DEFINED ENV{IDF_PATH})
  # Include both C and C++ source files for ESP-IDF build
  file(GLOB ESP32_C_CODES "./src/*.c")
  file(GLOB ESP32_CXX_CODES "./src/*.cpp")
  set(ESP32_CODES ${ESP32_C_CODES} ${ESP32_CXX_CODES})
  
  # Remove sctp.cpp from sources since we're disabling DATACHANNEL
  list(REMOVE_ITEM ESP32_CXX_CODES "./src/sctp.cpp")
  set(ESP32_CODES ${ESP32_C_CODES} ${ESP32_CXX_CODES})
  
  idf_component_register(
   SRCS ${ESP32_CODES}
   INCLUDE_DIRS "./include"
   PRIV_INCLUDE_DIRS "./src" 
   REQUIRES mbedtls esp_netif nvs_flash
   PRIV_REQUIRES libsrtp
  )
  
  # Set C++ standard for ESP-IDF
  target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
  
  # ESP32-specific compile definitions
  target_compile_definitions(${COMPONENT_LIB} PRIVATE
    CONFIG_USE_LWIP=1
    CONFIG_ENABLE_DATACHANNEL=0
    CONFIG_AUDIO_BUFFER_SIZE=2048
    CONFIG_DATA_BUFFER_SIZE=4096
    __BYTE_ORDER=__LITTLE_ENDIAN
  )
  
  # ESP32-specific compile options
  target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wno-unused-variable
    -Wno-unused-function
    -Wno-format-truncation
    -Wno-format
  )
  
  return()
endif()

project(webrtc-iot LANGUAGES C CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(ENABLE_TESTS "Enable tests" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(ADDRESS_SANITIZER "Build with AddressSanitizer." OFF)
option(MEMORY_SANITIZER "Build with MemorySanitizer." OFF)
option(THREAD_SANITIZER "Build with ThreadSanitizer." OFF)
option(UNDEFINED_BEHAVIOR_SANITIZER "Build with UndefinedBehaviorSanitizer." OFF)

include(ExternalProject)

include_directories(${CMAKE_BINARY_DIR}/dist/include)

link_directories(${CMAKE_BINARY_DIR}/dist/lib)

set(DEP_LIBS "srtp2" "usrsctp" "mbedtls" "mbedcrypto" "mbedx509")
# Extended debug information (symbols, source code, and macro definitions)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3")

function(enableSanitizer SANITIZER)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g -fsanitize=${SANITIZER} -fno-omit-frame-pointer -fno-optimize-sibling-calls" PARENT_SCOPE)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=${SANITIZER}" PARENT_SCOPE)
endfunction()

if(ADDRESS_SANITIZER)
  enableSanitizer("address")
endif()

if(MEMORY_SANITIZER)
  enableSanitizer("memory")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize-memory-track-origins")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-memory-track-origins")
endif()

if(THREAD_SANITIZER)
  enableSanitizer("thread")
endif()

if(UNDEFINED_BEHAVIOR_SANITIZER)
  enableSanitizer("undefined")
endif()


# Set common flags for both C and C++
add_definitions("-Wunused-variable -Werror=sequence-point -Werror=return-type -Werror=sizeof-pointer-memaccess")

# Set C-specific flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=pointer-sign -Wincompatible-pointer-types")

# C++ doesn't need these C-specific flags

add_subdirectory(src)

if(ENABLE_TESTS)
  add_subdirectory(tests)
endif()

# cJSON removed - no longer needed for signaling

ExternalProject_Add(mbedtls
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls
  CMAKE_ARGS
    -DCMAKE_C_FLAGS="-fPIC"
    -DENABLE_TESTING=off
    -DENABLE_PROGRAMS=off
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/dist
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls/include/mbedtls/mbedtls_config.h INPUT_CONTENT)
string(REPLACE "//#define MBEDTLS_SSL_DTLS_SRTP" "#define MBEDTLS_SSL_DTLS_SRTP" MODIFIED_CONTENT ${INPUT_CONTENT})
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls/include/mbedtls/mbedtls_config.h ${MODIFIED_CONTENT})

ExternalProject_Add(srtp2
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libsrtp
  CMAKE_ARGS
    -DCMAKE_C_FLAGS="-fPIC"
    -DTEST_APPS=off
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/dist
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
)

ExternalProject_Add(usrsctp
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/usrsctp
  CMAKE_ARGS
    -DCMAKE_C_FLAGS="-fPIC"
    -Dsctp_build_programs=off
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/dist
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
)
