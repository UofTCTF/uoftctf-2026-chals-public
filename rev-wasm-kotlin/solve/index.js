import { readFileSync, writeFileSync } from 'fs';

import { WASI } from 'wasi';
import { argv, env } from 'node:process';
import transformWasm from './hook.js';


const preWasmBuffer = readFileSync("../dist/program.wasm");
const wasmBuffer = transformWasm(preWasmBuffer, {
    'i32.ne': [['i32', 'i32'], ['i32']],
});

const wasi = new WASI({ version: 'preview1', args: argv, env, });

const wasmModule = new WebAssembly.Module(wasmBuffer);
const imports = Object.assign({}, wasi.getImportObject());
imports.hook = {
    "i32.ne": (a, b) => {
        if (a !== b) {
            console.log(`HOOK[i32.ne] result=1 with ${a} != ${b}`);
        }
        return (a !== b) ? 1 : 0;
    }
}
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);

wasi.initialize(wasmInstance);

const exports = wasmInstance.exports

export const {
memory,
_initialize
} = exports


