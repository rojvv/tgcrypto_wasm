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

function checkCtrParams(
  data: Uint8Array,
  key: Uint8Array,
) {
  if (data.byteLength == 0) {
    throw new TypeError("data must not be empty");
  } else if (key.byteLength != 32) {
    throw new TypeError("key must be 32 bytes");
  }
}

export interface Ctr256State {
  statep: number;
  ivp: number;
}
export function createCtr256State(iv: Uint8Array): Ctr256State {
  if (iv.byteLength != 16) {
    throw new TypeError("iv must be 16 bytes");
  }
  const state = {
    ivp: module_._malloc(16),
    statep: module_._malloc(1),
  };
  module_.HEAPU8.set(iv, state.ivp);
  module_.HEAPU8[state.statep] = 0
  return state;
}
export function destroyCtr256State(state: Ctr256State) {
  module_._free(state.ivp);
  module_._free(state.statep);
}
export interface __Ctr256StateValues {
  iv: Uint8Array;
  state: Uint8Array;
}
export function __getCtr256StateValues(
  state: Ctr256State,
): __Ctr256StateValues {
  return {
    iv: module_.HEAPU8.slice(state.ivp, state.ivp + 16),
    state: module_.HEAPU8.slice(state.statep, state.statep + 1),
  };
}
export function __settCtr256StateState(state: Ctr256State, state_: Uint8Array) {
  if (state_.byteLength != 1) {
    throw new Error("state_ must be 1 byte");
  }

  module_.HEAPU8.set(state_, state.statep);
}

/**
 * Performs CTR-256 encryption/decryption.
 *
 * @param data The data, larger than a byte
 * @param key 32-byte encryption key
 * @param iv 16-byte initialization vector
 * @param state Result of `createCtr256State()`
 */
export function ctr256(
  data: Uint8Array,
  key: Uint8Array,
  state: Ctr256State,
) {
  checkCtrParams(data, key);
  const datap = module_._malloc(data.byteLength);
  module_.HEAPU8.set(data, datap);

  module_.ccall(
    "ctr256",
    "void",
    ["pointer", "number", "array", "pointer", "pointer"],
    [datap, data.byteLength, key, state.ivp, state.statep],
  );
  data.set(module_.HEAPU8.slice(datap, datap + data.byteLength));
  module_._free(datap);
}

function checkCbcParams(data: Uint8Array, key: Uint8Array, iv: Uint8Array) {
  if (data.byteLength == 0) {
    throw new TypeError("data must not be empty");
  } else if (data.byteLength % 16 != 0) {
    throw new TypeError(
      "data must consist of a number of bytes that is divisible by 16",
    );
  } else if (key.byteLength != 32) {
    throw new TypeError("key must be 32 bytes");
  } else if (iv.byteLength != 16) {
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
  const datap = module_._malloc(data.byteLength);
  module_.HEAPU8.set(data, datap);
  module_.ccall(
    "cbc256_encrypt",
    "void",
    ["pointer", "number", "array", "array"],
    [datap, data.byteLength, key, iv],
  );
  try {
    return module_.HEAPU8.slice(datap, datap + data.byteLength);
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
  const datap = module_._malloc(data.byteLength);
  module_.HEAPU8.set(data, datap);
  module_.ccall(
    "cbc256_decrypt",
    "void",
    ["pointer", "number", "array", "array"],
    [datap, data.byteLength, key, iv],
  );
  try {
    return module_.HEAPU8.slice(datap, datap + data.byteLength);
  } finally {
    module_._free(datap);
  }
}
