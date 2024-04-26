cmake_minimum_required(VERSION 3.28)
project(libbg3 LANGUAGES C CXX)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)

add_subdirectory(third_party/pybind11)
add_library(libbg3_third_party STATIC
  third_party/lz4.c
  third_party/lz4frame.c
  third_party/lz4hc.c
  third_party/miniz.c
  third_party/xxhash.c)
target_include_directories(libbg3_third_party PUBLIC third_party)
add_executable(bg3_find examples/bg3_find.c)
target_link_libraries(bg3_find libbg3_third_party)
add_executable(bg3_index examples/bg3_index.c)
target_link_libraries(bg3_index libbg3_third_party)
add_executable(granny examples/granny.c)
target_link_libraries(granny libbg3_third_party)
add_executable(lspk examples/lspk.c)
target_link_libraries(lspk libbg3_third_party)
add_executable(osiris examples/osiris.c)
target_link_libraries(osiris libbg3_third_party)
pybind11_add_module(_pybg3 examples/pybg3.cc)
target_link_libraries(_pybg3 PRIVATE libbg3_third_party)