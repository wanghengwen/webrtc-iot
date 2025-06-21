project(lib)

# Separate C and C++ source files
file(GLOB C_SRCS "*.c")
file(GLOB CXX_SRCS "*.cpp")


file(GLOB HEADERS "../include/*.h" "../include/*.hpp")

add_library(webrtc-iot
  ${C_SRCS}
  ${CXX_SRCS}
)

target_include_directories(webrtc-iot PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}
)

add_dependencies(webrtc-iot mbedtls usrsctp srtp2)

target_link_libraries(webrtc-iot ${DEP_LIBS})

set_target_properties(webrtc-iot PROPERTIES PUBLIC_HEADER "${HEADERS}")

install(TARGETS webrtc-iot
  LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include/
)

