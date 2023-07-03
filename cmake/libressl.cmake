include(ExternalProject)

ExternalProject_Add(
    libressl
    URL      https://cloudflare.cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.7.3.tar.gz

    DOWNLOAD_DIR "_deps/libressl-src"
    LOG_DIR "_deps/libressl-log"
    STAMP_DIR "_deps/libressl-stamp"
    TMP_DIR "_deps/libressl-tmp"
    SOURCE_DIR "_deps/libressl-src"
    BINARY_DIR "_deps/libressl-build"
    INSTALL_DIR "_deps/libressl-install"


    # Which components should be bundled:
    # https://arrow.apache.org/docs/developers/cpp/building.html#build-dependency-management
    INSTALL_COMMAND ""
)

ExternalProject_Get_Property(libressl SOURCE_DIR)
ExternalProject_Get_Property(libressl BINARY_DIR)
ExternalProject_Get_Property(libressl INSTALL_DIR)

include_directories(${SOURCE_DIR}/include)

add_library(libressl::crypto STATIC IMPORTED)
set_property(TARGET libressl::crypto PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/crypto/libcrypto.a)
add_dependencies(libressl::crypto libressl)

add_library(libressl::ssl STATIC IMPORTED)
set_property(TARGET libressl::ssl PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/ssl/libssl.a)
add_dependencies(libressl::ssl libressl)

add_library(libressl::tls STATIC IMPORTED)
set_property(TARGET libressl::tls PROPERTY IMPORTED_LOCATION ${BINARY_DIR}/tls/libtls.a)
add_dependencies(libressl::tls libressl)
