#!/bin/bash
wasm-opt \
    --enable-gc \
    --enable-bulk-memory \
    --enable-exception-handling \
    --enable-reference-types \
    ./build/compileSync/wasmWasi/main/productionExecutable/kotlin/rev-wasm.wasm \
    --output dist/program.wasm -O3

node minimize.mjs \
    ./dist/program.wasm \
    ./dist/program.wasm 