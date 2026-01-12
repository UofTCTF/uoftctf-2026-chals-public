// To run the wasm with runner.mjs, ensure you have Node.js v22 or later installed.
import { WASI } from 'wasi';
import { argv, env } from 'node:process';


const wasi = new WASI({ version: 'preview1', args: argv, env, });

const fs = await import('node:fs');
const url = await import('node:url');
const wasmBuffer = fs.readFileSync(url.fileURLToPath(import.meta.resolve('./program.wasm')));
const wasmModule = new WebAssembly.Module(wasmBuffer);
const wasmInstance = new WebAssembly.Instance(wasmModule, wasi.getImportObject());

wasi.initialize(wasmInstance);

const exports = wasmInstance.exports

export const {
memory,
_initialize
} = exports


