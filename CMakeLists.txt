cmake_minimum_required(VERSION 3.9)
project(secp256k1 VERSION 1.0.0 DESCRIPTION "SECP256K1 utilities library")

include(GNUInstallDirs)

if (NOT TARGET hashing)
# Hashing functions library
add_subdirectory(extras/hashing)
endif()

set(secp256k1_src
   src/sign.c
   src/add_scalar.c
   src/keypair.c
   src/verify.c
   extras/micro-secp256k1/uECC.c
)

if (NOT TARGET secp256k1)
add_library(secp256k1 ${secp256k1_src})
target_link_libraries(secp256k1 hashing)
target_include_directories(secp256k1 PRIVATE include)
target_include_directories(secp256k1 PRIVATE extras/hashing/include)
target_include_directories(secp256k1 PRIVATE extras/micro-secp256k1)

set_target_properties(secp256k1 PROPERTIES
   VERSION ${PROJECT_VERSION}
   POSITION_INDEPENDENT_CODE 1
   PUBLIC_HEADER "include/secp256k1.h"
)

install(TARGETS secp256k1
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if (BUILD_UTILS)
add_executable(create_keypair_secp256k1 misc/create_keypair.c)
target_include_directories(create_keypair_secp256k1 PRIVATE include)
target_link_libraries(create_keypair_secp256k1 secp256k1 $<$<PLATFORM_ID:Linux>:bsd>)
endif()
endif()

configure_file(secp256k1.pc.in secp256k1.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/secp256k1.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
