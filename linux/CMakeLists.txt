cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME "flutter_pkcs12")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "flutter_pkcs12_plugin")
set (OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

#link_directories("${CMAKE_CURRENT_SOURCE_DIR}/lib")

add_library(${PLUGIN_NAME} SHARED
  "flutter_pkcs12_plugin.cc"
)

apply_standard_settings(${PLUGIN_NAME})
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::GTK)
target_link_libraries(${PLUGIN_NAME} PRIVATE OpenSSL::Crypto)
target_link_libraries(${PLUGIN_NAME} PRIVATE OpenSSL::SSL)

# List of absolute paths to libraries that should be bundled with the plugin
set(flutter_pkcs12_bundled_libraries
  ""
  PARENT_SCOPE
)
