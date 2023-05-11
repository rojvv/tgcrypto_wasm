cmake_minimum_required(VERSION 3.25)
project("tgcrypto_wasm")

include_directories(third_party/tgcrypto/tgcrypto)

file(GLOB TGCRYPTO_SOURCES third_party/tgcrypto/tgcrypto/*256.c)

set(CMAKE_EXECUTABLE_SUFFIX ".js")

add_executable(tgcrypto ${TGCRYPTO_SOURCES} src/tgcrypto.cpp)
set_target_properties(
    tgcrypto
    PROPERTIES
    LINK_FLAGS "-lembind -s SINGLE_FILE=1 -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s EXPORT_ES6=1 -sMODULARIZE -O3 -sWASM_BIGINT" 
    RUNTIME_OUTPUT_DIRECTORY "dist/"
)
