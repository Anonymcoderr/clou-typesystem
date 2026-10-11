# Type checker. Plain C++, no LLVM or Z3, so it builds and tests on its own.

add_library(axtypes STATIC
  typecheck.cc typecheck.h
  graph.h
  lattice.h
  )
target_include_directories(axtypes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(axtypes PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(axtypes_test test_axtypes.cc)
target_link_libraries(axtypes_test PRIVATE axtypes)

add_test(NAME axtypes_unit COMMAND axtypes_test)
