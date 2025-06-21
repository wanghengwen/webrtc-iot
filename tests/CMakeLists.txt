project(tests)

file(GLOB C_SRCS "*.c")
file(GLOB CXX_SRCS "*.cpp")

include_directories(${PROJECT_SOURCE_DIR}/../src)
include_directories(${PROJECT_SOURCE_DIR}/../include)

# Handle C test files
foreach(sourcefile ${C_SRCS})
  string(REPLACE ".c" "" appname ${sourcefile})
  string(REPLACE "${PROJECT_SOURCE_DIR}/" "" appname ${appname})
  add_executable(${appname} ${sourcefile})
  target_link_libraries(${appname} webrtc-iot pthread)
endforeach(sourcefile)

# Handle C++ test files
foreach(sourcefile ${CXX_SRCS})
  string(REPLACE ".cpp" "" appname ${sourcefile})
  string(REPLACE "${PROJECT_SOURCE_DIR}/" "" appname ${appname})
  add_executable(${appname} ${sourcefile})
  target_link_libraries(${appname} webrtc-iot pthread)
endforeach(sourcefile)

# No special linking needed - cjson removed

