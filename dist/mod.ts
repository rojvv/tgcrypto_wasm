import { default as init_ } from "./tgcrypto.js";

// deno-lint-ignore no-explicit-any
let module_: any;
const promise = init_().then((v: typeof module_) => module_ = v);

export async function init() {
  await promise;
}

function checkIgeParams(data: Uint8Array, key: Uint8Array, iv: Uint8Array) {
  if (data.byteLength == 0) {
    throw new TypeError("data must not be empty");
  } else if (data.byteLength % 16 != 0) {
    throw new TypeError(
      "data must consist of a number of bytes that is divisible by 16",
    );
  } else if (key.byteLength != 32) {
    throw new TypeError("key must be 32 bytes");
  } else if (iv.byteLength != 32) {
    throw new TypeError("iv must be 32 bytes");
  }
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
): Uint8Array {
  checkIgeParams(data, key, iv);
  const out = module_._malloc(data.byteLength);
  const datap = module_._malloc(data.byteLength);
  module_.HEAPU8.set(data, datap);
  module_.ccall(
    "ige256_encrypt",
    "void",
    ["pointer", "pointer", "number", "array", "array"],
    [datap, out, data.byteLength, key, iv],
  );
  try {
    return module_.HEAPU8.slice(out, out + data.byteLength);
  } finally {
    module_._free(out);
    module_._free(datap);
  }
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
): Uint8Array {
  checkIgeParams(data, key, iv);
  const out = module_._malloc(data.byteLength);
  const datap = module_._malloc(data.byteLength);
  module_.HEAPU8.set(data, datap);
  module_.ccall(
    "ige256_decrypt",
    "void",
    ["pointer", "pointer", "number", "array", "array"],
    [datap, out, data.byteLength, key, iv],
  );
  try {
    return module_.HEAPU8.slice(out, out + data.byteLength);
  } finally {
    module_._free(out);
    module_._free(datap);
  }
}
