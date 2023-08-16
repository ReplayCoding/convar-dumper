cmake_minimum_required(VERSION 3.14)

project("cvdumper")

option(SDK_USE_CXX11_ABI "" ON)
# CPMAddPackage(
#   NAME source-sdk
#   GITHUB_REPOSITORY ReplayCoding/hl2sdk-cmake
#   GIT_TAG 4ef9cdbda59f1ea07a23c518fa00bea0aac45642
# )

add_subdirectory(hl2sdk-cmake)

find_package(LIEF REQUIRED)
find_package(fmt REQUIRED)
find_package(nlohmann_json REQUIRED)

add_compile_options(-fpermissive)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(cvdumper main.cpp)
target_link_libraries(
  cvdumper PRIVATE
  sdk::tier0
  sdk::tier1
  sdk::tier2
  sdk::tier3
  fmt::fmt
  LIEF::LIEF
  nlohmann_json::nlohmann_json
)
