import { cbc256Decrypt, cbc256Encrypt, init } from "../dist/mod.ts";
import { assertEquals } from "./deps.ts";

await init();

const DATA_SIZE = 64;
const KEY_SIZE = 32;
const IV_SIZE = 16;
const ITERATION_COUNT = 500;

Deno.test("random", async (t) => {
  await t.step("encrypt decrypt", () => {
    for (let i = 0; i < ITERATION_COUNT; i++) {
      const data = new Uint8Array(DATA_SIZE);
      const key = new Uint8Array(KEY_SIZE);
      const iv = new Uint8Array(IV_SIZE);

      crypto.getRandomValues(data);
      crypto.getRandomValues(key);
      crypto.getRandomValues(iv);

      const a = cbc256Encrypt(data, key, iv);
      const b = cbc256Decrypt(a, key, iv);

      assertEquals(b, data);
    }
  });

  await t.step("decrypt encrypt", () => {
    for (let i = 0; i < ITERATION_COUNT; i++) {
      const data = new Uint8Array(DATA_SIZE);
      const key = new Uint8Array(KEY_SIZE);
      const iv = new Uint8Array(IV_SIZE);

      crypto.getRandomValues(data);
      crypto.getRandomValues(key);
      crypto.getRandomValues(iv);

      const a = cbc256Encrypt(data, key, iv);
      const b = cbc256Decrypt(a, key, iv);

      assertEquals(b, data);
    }
  });
});
