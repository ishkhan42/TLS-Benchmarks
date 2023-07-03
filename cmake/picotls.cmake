include(FetchContent)

FetchContent_Declare(
  picotls
  GIT_REPOSITORY https://github.com/h2o/picotls.git
  GIT_TAG master
)

FetchContent_MakeAvailable(picotls)
include_directories(${picotls_SOURCE_DIR}/include)

