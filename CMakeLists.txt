cmake_minimum_required(VERSION 3.22.1)
project("tgcrypto_wasm")

include_directories(third_party/tgcrypto/tgcrypto)

file(GLOB TGCRYPTO_SOURCES third_party/tgcrypto/tgcrypto/*256.c)

set(CMAKE_EXECUTABLE_SUFFIX ".js")

add_executable(tgcrypto ${TGCRYPTO_SOURCES} src/tgcrypto.c)
target_compile_options(tgcrypto PRIVATE -O3 -flto)
set_target_properties(
    tgcrypto
    PROPERTIES
    LINK_FLAGS "-s SINGLE_FILE=1 -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s ENVIRONMENT=web -s EXPORT_ES6=1 -O3 -flto -sWASM_BIGINT -s EXPORTED_FUNCTIONS=_malloc,_free -sALLOW_MEMORY_GROWTH"
    RUNTIME_OUTPUT_DIRECTORY "dist/"
)
