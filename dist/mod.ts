import { default as init_ } from "./tgcrypto.js";

// deno-lint-ignore no-explicit-any
function collectVector(vector: any) {
  const p = new Uint8Array(vector.size());
  for (let i = 0; i < vector.size(); i++) {
    p[i] = vector.get(i);
  }
  vector.delete();
  return p;
}

// deno-lint-ignore no-explicit-any
let module_: any;
const promise = init_().then((v: typeof module_) => module_ = v);

export async function init() {
  await promise;
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
  return collectVector(module_.ige256Encrypt(data, key, iv));
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
  return collectVector(module_.ige256Decrypt(data, key, iv));
}

/**
 * Performs CTR-256 encryption.
 *
 * @param data The data, larger than a byte
 * @param key 32-byte encryption key
 * @param iv 16-byte initialization vector
 * @param state 1-byte state
 */
export function ctr256Encrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  state: Uint8Array,
): [Uint8Array, Uint8Array, Uint8Array] {
  const r = module_.ctr256Encrypt(data, key, iv, state);
  return r.map(collectVector);
}

/**
 * Alias of `ctr256Encrypt`
 */
export function ctr256Decrypt(
  data: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
  state: Uint8Array,
): [Uint8Array, Uint8Array, Uint8Array] {
  const r = module_.ctr256Decrypt(data, key, iv, state);
  return r.map(collectVector);
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
  return collectVector(module_.cbc256Encrypt(data, key, iv));
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
  return collectVector(module_.cbc256Decrypt(data, key, iv));
}

export function factorize(pq: bigint): [bigint, bigint] {
  const vector = module_.factorize(pq);
  return [vector.get(0), vector.get(1)];
}
