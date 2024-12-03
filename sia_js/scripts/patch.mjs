import fs from 'node:fs/promises';

const packageName = 'sia_js';
const wasmFilename = 'sia_js_bg.wasm';
const jsFilename = 'sia_js.js';

const rawWasmFile = await fs.readFile(`pkg/${wasmFilename}`);
const origJsFile = await fs.readFile(`pkg/${jsFilename}`, 'utf8');

const base64 = rawWasmFile.toString('base64');

// Remove NodeJS specific APIs and inline WASM.
const patchedJsFile = origJsFile
    // TextEncoder and TextDecoder are globally available in NodeJS and browsers.
    // inspect and inspect.custom are NodeJS specific APIs, replace with polyfill.
    .replace('const { TextEncoder, TextDecoder, inspect } = require(`util`);',`
const inspect = (obj) => JSON.stringify(obj, null, 2); `)
    .replace('[inspect.custom]', `[Symbol.for('nodejs.util.inspect.custom')]`)
    // Inline WASM.
    .replace(`const path = require('path').join(__dirname, '${wasmFilename}');`, '')
    .replace(`const bytes = require('fs').readFileSync(path);`, `
const wasmBase64 = '${base64}';
const bytes = Uint8Array.from(atob(wasmBase64), c => c.charCodeAt(0));`);

await fs.writeFile(`pkg/${jsFilename}`, patchedJsFile);

// Remove WASM files.
await fs.unlink(`pkg/${wasmFilename}`);
await fs.unlink(`pkg/${wasmFilename}.d.ts`);

// Remove WASM from .files section of package.json.
const pkgJsonFile = await fs.readFile('pkg/package.json', 'utf8');
const pkgJson = JSON.parse(pkgJsonFile);
pkgJson.name = packageName;
pkgJson.files = pkgJson.files.filter(file => file !== wasmFilename);
await fs.writeFile('pkg/package.json', JSON.stringify(pkgJson, null, 2));
