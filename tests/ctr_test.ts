import { ctr256, init } from "../dist/mod.ts";
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
      const state = new Uint8Array(1);

      crypto.getRandomValues(data);
      const copy = new Uint8Array(data);
      crypto.getRandomValues(key);
      crypto.getRandomValues(iv);

      ctr256(data, key, iv, state);
      ctr256(data, key, iv, state);

      assertEquals(copy, data);
    }
  });

  await t.step("decrypt encrypt", () => {
    for (let i = 0; i < ITERATION_COUNT; i++) {
      const data = new Uint8Array(DATA_SIZE);

      const key = new Uint8Array(KEY_SIZE);
      const iv = new Uint8Array(IV_SIZE);
      const state = new Uint8Array(1);

      crypto.getRandomValues(data);
      const copy = new Uint8Array(data);
      crypto.getRandomValues(key);
      crypto.getRandomValues(iv);

      ctr256(data, key, iv, state);
      ctr256(data, key, iv, state);

      assertEquals(copy, data);
    }
  });
});
