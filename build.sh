#!/bin/bash
docker build -t tgcrypto_wasm . &&
docker run --rm -v .:/build tgcrypto_wasm &&
deno fmt
