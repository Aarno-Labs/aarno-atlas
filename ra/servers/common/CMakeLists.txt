file(GLOB CPP_SOURCES
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.cpp
)

set(TARGET sediment_server)

add_library(${TARGET}
  ${CPP_SOURCES}
)
