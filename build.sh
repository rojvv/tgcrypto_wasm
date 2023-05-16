source ~/emsdk/emsdk_env.sh 2>/dev/null
emmake cmake .
emmake cmake --build .
mv dist/node/tgcrypto-node.js dist/node/tgcrypto.js
deno fmt
