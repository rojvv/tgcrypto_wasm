import { default as init_ } from "./tgcrypto.js";

// deno-lint-ignore no-explicit-any
let module_: any;
const promise = init_().then((v: typeof module_) => module_ = v);

let workspace = 0;
let workspaceCapacity = 0;

export async function init() {
  await promise;
}

function checkIgeParams(data: Uint8Array, key: Uint8Array, iv: Uint8Array) {
  if (data.byteLength === 0) {
    throw new TypeError("data must not be empty");
  } else if (data.byteLength % 16 !== 0) {
    throw new TypeError(
      "data must consist of a number of bytes that is divisible by 16",
    );
  } else if (key.byteLength !== 32) {
    throw new TypeError("key must be 32 bytes");
  } else if (iv.byteLength !== 32) {
    throw new TypeError("iv must be 32 bytes");
  }
}

function ensureWorkspace(requiredCapacity: number) {
  if (workspaceCapacity >= requiredCapacity) return;

  let capacity = Math.max(1024, workspaceCapacity);
  while (capacity < requiredCapacity) capacity *= 2;

  // Input, output, key and IV share one allocation. Allocate first so a
  // failure does not discard the current workspace.
  const nextWorkspace = module_._malloc(capacity * 2 + 64);
  if (nextWorkspace === 0) {
    throw new RangeError("could not allocate WASM memory");
  }

  if (workspace !== 0) module_._free(workspace);
  workspace = nextWorkspace;
  workspaceCapacity = capacity;
}

function processIge(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  encrypt: boolean,
): Uint8Array<ArrayBuffer> {
  checkIgeParams(data, key, iv);
  ensureWorkspace(data.byteLength);

  const input = workspace;
  const output = input + workspaceCapacity;
  const keyPointer = output + workspaceCapacity;
  const ivPointer = keyPointer + 32;

  module_.HEAPU8.set(data, input);
  module_.HEAPU8.set(key, keyPointer);
  module_.HEAPU8.set(iv, ivPointer);

  const transform = encrypt ? module_._ige256_encrypt : module_._ige256_decrypt;
  transform(input, output, data.byteLength, keyPointer, ivPointer);

  return module_.HEAPU8.slice(output, output + data.byteLength);
}

/**
 * Performs IGE-256 encryption.
 *
 * @param data The unencrypted data, larger than a byte, divisible by 16
 * @param key 32-byte encryption key
 * @param iv 32-byte initialization vector
 */
export function ige256Encrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array<ArrayBuffer> {
  return processIge(data, key, iv, true);
}

/**
 * Performs IGE-256 decryption.
 *
 * @param data The encrypted data, larger than a byte, divisible by 16
 * @param key 32-byte encryption key
 * @param iv 32-byte initialization vector
 */
export function ige256Decrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array<ArrayBuffer> {
  return processIge(data, key, iv, false);
}
