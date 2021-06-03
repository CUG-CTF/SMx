find_package(OpenSSL REQUIRED)

add_library(SMx SHARED SMx.h SM2.c SM3.c SM4.c)
target_link_libraries(SMx OpenSSL::Crypto)

add_executable(SMx_test SMx_test.c)
target_link_libraries(SMx_test SMx)