// Minimizes in place

if (process.argv.length !== 4) {
    console.error("Usage: node minimize.js <wasm-file> <output>");
    process.exit(1);
}
const path = process.argv[2];
const outputPath = process.argv[3];

import fs from 'fs';

const wasmBuffer = fs.readFileSync(path);

class BufferView {
    constructor(buffer) {
        this.buffer = buffer;
        this.offset = 0;
        this.size = buffer.length;
    }

    readVu32() {
        let value = 0;
        let shift = 0;
        let byte;
        do {
            byte = this.buffer[this.offset++];
            value |= (byte & 0x7F) << shift;
            shift += 7;
        } while (byte & 0x80);
        return value;
    }

    writeVu32(value) {
        do {
            let byte = value & 0x7F;
            value >>>= 7;
            if (value !== 0) {
                byte |= 0x80;
            }
            this.buffer[this.offset++] = byte;
        } while (value !== 0);
    }

    writeBuffer(srcBuffer) {
        srcBuffer.copy(this.buffer, this.offset);
        this.offset += srcBuffer.length;
    }
    readBuffer(length) {
        const outBuffer = this.buffer.slice(this.offset, this.offset + length);
        this.offset += length;
        return outBuffer;
    }
}
const input = new BufferView(wasmBuffer);
// We're cutting down bytes, size will get shorter
const output = new BufferView(Buffer.alloc(wasmBuffer.length + 128));

output.writeBuffer(input.readBuffer(8)); // Magic + version

// Delete useless section
while (input.offset < input.size) {
    const sectionId = input.readVu32();
    const sectionSize = input.readVu32();
    const sectionBytes = input.readBuffer(sectionSize);
    if (sectionId === 0) { // Custom section
        continue;
    }
    // Otherwise copy it over
    output.writeVu32(sectionId);
    output.writeVu32(sectionSize);
    output.writeBuffer(sectionBytes);
}

fs.writeFileSync(outputPath, output.buffer.slice(0, output.offset));