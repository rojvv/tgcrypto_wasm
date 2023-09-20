cmake_minimum_required(VERSION 3.25)
project("tgcrypto_wasm")

include_directories(third_party/tgcrypto/tgcrypto)

file(GLOB TGCRYPTO_SOURCES third_party/tgcrypto/tgcrypto/*256.c)

set(CMAKE_EXECUTABLE_SUFFIX ".js")

add_executable(tgcrypto ${TGCRYPTO_SOURCES} src/tgcrypto.c)
add_executable(tgcrypto-node ${TGCRYPTO_SOURCES} src/tgcrypto.c)
set_target_properties(
    tgcrypto
    PROPERTIES
    LINK_FLAGS "-lembind -s SINGLE_FILE=1 -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s ENVIRONMENT=web -s EXPORT_ES6=1 -O3 -sWASM_BIGINT -s EXPORTED_FUNCTIONS=\"['_malloc','_free']\" -sEXPORTED_RUNTIME_METHODS=ccall" 
    RUNTIME_OUTPUT_DIRECTORY "dist/"
)
set_target_properties(
    tgcrypto-node
    PROPERTIES
    LINK_FLAGS "-lembind -s SINGLE_FILE=1 -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s ENVIRONMENT=node -s EXPORT_ES6=1 -O3 -sWASM_BIGINT -s EXPORTED_FUNCTIONS=\"['_malloc','_free']\" -sEXPORTED_RUNTIME_METHODS=ccall" 
    RUNTIME_OUTPUT_DIRECTORY "dist/node/"
)
