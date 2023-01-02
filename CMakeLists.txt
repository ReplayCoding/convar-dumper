cmake_minimum_required(VERSION 3.14)

project("nvdumper")

set(CPM_DOWNLOAD_VERSION 0.34.0)

if(CPM_SOURCE_CACHE)
  set(CPM_DOWNLOAD_LOCATION "${CPM_SOURCE_CACHE}/cpm/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
elseif(DEFINED ENV{CPM_SOURCE_CACHE})
  set(CPM_DOWNLOAD_LOCATION "$ENV{CPM_SOURCE_CACHE}/cpm/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
else()
  set(CPM_DOWNLOAD_LOCATION "${CMAKE_BINARY_DIR}/cmake/CPM_${CPM_DOWNLOAD_VERSION}.cmake")
endif()

if(NOT (EXISTS ${CPM_DOWNLOAD_LOCATION}))
  message(STATUS "Downloading CPM.cmake to ${CPM_DOWNLOAD_LOCATION}")
  file(DOWNLOAD
       https://github.com/TheLartians/CPM.cmake/releases/download/v${CPM_DOWNLOAD_VERSION}/CPM.cmake
       ${CPM_DOWNLOAD_LOCATION}
  )
endif()

include(${CPM_DOWNLOAD_LOCATION})
CPMAddPackage(
  NAME source-sdk
  GITHUB_REPOSITORY ReplayCoding/hl2sdk-cmake
  GIT_TAG 92b751c8
)

CPMAddPackage("gh:fmtlib/fmt#9.1.0")
CPMAddPackage("gh:ericniebler/range-v3#0.12.0")
CPMAddPackage("gh:nlohmann/json#v3.11.2")

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(nvdumper main.cpp)
target_link_libraries(
  nvdumper PRIVATE
  sdk::tier0
  sdk::tier1
  sdk::tier2
  sdk::tier3
  fmt::fmt-header-only
  range-v3::range-v3
  nlohmann_json::nlohmann_json
)
