include(ExternalProject)

ExternalProject_Add(
    boringssl
    GIT_REPOSITORY      https://boringssl.googlesource.com/boringssl
    GIT_TAG master


    DOWNLOAD_DIR "_deps/boringssl-src"
    LOG_DIR "_deps/boringssl-log"
    STAMP_DIR "_deps/boringssl-stamp"
    TMP_DIR "_deps/boringssl-tmp"
    SOURCE_DIR "_deps/boringssl-src"
    BINARY_DIR "_deps/boringssl-build"
    INSTALL_DIR "_deps/boringssl-install"


    # Which components should be bundled:
    # https://arrow.apache.org/docs/developers/cpp/building.html#build-dependency-management
    INSTALL_COMMAND ""
)

ExternalProject_Get_Property(boringssl SOURCE_DIR)
ExternalProject_Get_Property(boringssl BINARY_DIR)
ExternalProject_Get_Property(boringssl INSTALL_DIR)

include_directories(${SOURCE_DIR}/include)

add_library(boringssl::crypto STATIC IMPORTED)
set_property(TARGET boringssl::crypto PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/crypto/libcrypto.a)
add_dependencies(boringssl::crypto boringssl)

add_library(boringssl::ssl STATIC IMPORTED)
set_property(TARGET boringssl::ssl PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/ssl/libssl.a)
add_dependencies(boringssl::ssl boringssl)