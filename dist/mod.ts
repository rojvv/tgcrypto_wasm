import init from "./tgcrypto.js";

const module = await init();

export function ige256Encrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  return module.ige256Encrypt(data, key, iv);
}

export function ige256Decrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  return module.ige256Decrypt(data, key, iv);
}

export function ctr256Encrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  state: Uint8Array,
): [Uint8Array, Uint8Array, Uint8Array] {
  return module.ctr256Encrypt(data, key, iv, state);
}

export function ctr256Decrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  state: Uint8Array,
): [Uint8Array, Uint8Array, Uint8Array] {
  return module.ctr256Decrypt(data, key, iv, state);
}

export function cbc256Encrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  return module.cbc256Encrypt(data, key, iv);
}

export function cbc256Decrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Uint8Array {
  return module.cbc256Decrypt(data, key, iv);
}
