#!/bin/bash
docker build -t tgcrypto_wasm . &&
docker run -it --rm -v .:/build tgcrypto_wasm &&
deno fmt
