import { default as init_ } from "./tgcrypto.js";

// deno-lint-ignore no-explicit-any
let module_: any;
const promise = init_().then((v: typeof module_) => module_ = v);

export async function init() {
  await promise;
}

function checkIgeParams(data: Uint8Array, key: Uint8Array, iv: Uint8Array) {
  if (data.length == 0) {
    throw new TypeError("data must not be empty");
  } else if (data.length % 16 != 0) {
    throw new TypeError(
      "data must consist of a number of bytes that is divisible by 16",
    );
  } else if (key.length != 32) {
    throw new TypeError("key must be 32 bytes");
  } else if (iv.length != 32) {
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
  const out = module_._malloc(1024);
  module_.ccall(
    "ige256_encrypt",
    "void",
    ["array", "pointer", "number", "array", "array"],
    [data, out, data.length, key, iv],
  );
  try {
    return module_.HEAPU8.slice(out, out + data.length);
  } finally {
    module_._free(out);
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
  const out = module_._malloc(1024);
  module_.ccall(
    "ige256_decrypt",
    "void",
    ["array", "pointer", "number", "array", "array"],
    [data, out, data.length, key, iv],
  );
  try {
    return module_.HEAPU8.slice(out, out + data.length);
  } finally {
    module_._free(out);
  }
}

function checkCtrParams(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  state: Uint8Array,
) {
  if (data.length == 0) {
    throw new TypeError("data must not be empty");
  } else if (key.length != 32) {
    throw new TypeError("key must be 32 bytes");
  } else if (iv.length != 16) {
    throw new TypeError("iv must be 16 bytes");
  } else if (state.length != 1) {
    throw new TypeError("state must be 1 byte");
  }
}

/**
 * Performs CTR-256 encryption/decryption.
 *
 * @param data The data, larger than a byte
 * @param key 32-byte encryption key
 * @param iv 16-byte initialization vector
 * @param state 1-byte state
 */
export function ctr256(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  state: Uint8Array,
) {
  checkCtrParams(data, key, iv, state);
  const datap = module_._malloc(data.length);
  module_.HEAPU8.set(data, datap);
  const ivp = module_._malloc(iv.length);
  module_.HEAPU8.set(iv, ivp);
  const statep = module_._malloc(state.length);
  module_.HEAPU8.set(state, statep);

  module_.ccall(
    "ctr256",
    ["pointer", "number", "array", "pointer", "pointer"],
    "void",
    [datap, data.length, key, ivp, statep],
  );
  data.set(module_.HEAPU8.slice(datap, datap + data.length));
  iv.set(module_.HEAPU8.slice(ivp, ivp + iv.length));
  state.set(module_.HEAPU8.slice(statep, statep + state.length));
  module_._free(datap);
  module_._free(ivp);
  module_._free(statep);
}

function checkCbcParams(data: Uint8Array, key: Uint8Array, iv: Uint8Array) {
  if (data.length == 0) {
    throw new TypeError("data must not be empty");
  } else if (data.length % 16 != 0) {
    throw new TypeError(
      "data must consist of a number of bytes that is divisible by 16",
    );
  } else if (key.length != 32) {
    throw new TypeError("key must be 32 bytes");
  } else if (iv.length != 16) {
    throw new TypeError("iv must be 16 bytes");
  }
}

/**
 * Performs CBC-256 encryption.
 *
 * @param data The unencrypted data, larger than a byte, divisible by 16
 * @param key 32-byte encryption key
 * @param iv 16-byte initialization vector
 */
export function cbc256Encrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  checkCbcParams(data, key, iv);
  const datap = module_._malloc(data.length);
  module_.HEAPU8.set(data, datap);
  module_.ccall(
    "cbc256_encrypt",
    ["pointer", "number", "array", "array"],
    "void",
    [datap, data.length, key, iv],
  );
  try {
    return module_.HEAPU8.slice(datap, datap + data.length);
  } finally {
    module_._free(datap);
  }
}

/**
 * Performs CBC-256 decryption.
 *
 * @param data The encrypted data, larger than a byte, divisible by 16
 * @param key 32-byte encryption key
 * @param iv 16-byte initialization vector
 */
export function cbc256Decrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  checkCbcParams(data, key, iv);
  const datap = module_._malloc(data.length);
  module_.HEAPU8.set(data, datap);
  module_.ccall(
    "cbc256_decrypt",
    ["pointer", "number", "array", "array"],
    "void",
    [datap, data.length, key, iv],
  );
  try {
    return module_.HEAPU8.slice(datap, datap + data.length);
  } finally {
    module_._free(datap);
  }
}

export function factorize(pq: bigint): [bigint, bigint] {
  const vector = module_.factorize(pq);
  return [vector.get(0), vector.get(1)];
}
