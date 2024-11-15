#!/bin/bash
cd /build &&
emmake cmake . &&
emmake cmake --build . &&

mv dist/node/tgcrypto-node.js dist/node/tgcrypto.js
