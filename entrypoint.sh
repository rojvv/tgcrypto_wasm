#!/bin/bash
cd /build &&
emmake cmake . &&
emmake cmake --build .
