import { ige256Decrypt, ige256Encrypt, init } from "../dist/mod.ts";
import { assertEquals } from "./deps.ts";

await init();

const DATA_SIZE = 64;
const KEY_SIZE = 32;
const IV_SIZE = 32;
const ITERATION_COUNT = 500;

Deno.test("expectancy", () => {
  // deno-fmt-ignore
  const expected =new Uint8Array([
    220, 149, 192, 120, 162,  64, 137, 137,
    173,  72, 162,  20, 146, 132,  32, 135,
      8, 195, 116, 132, 140,  34, 130,  51,
    194, 179,  79,  51,  43, 210, 233, 211
  ]);
  const actual = ige256Encrypt(
    new Uint8Array(32),
    new Uint8Array(32),
    new Uint8Array(32),
  );
  assertEquals(actual, expected);
  assertEquals(
    new Uint8Array(32),
    ige256Decrypt(expected, new Uint8Array(32), new Uint8Array(32)),
  );
});

Deno.test("random", async (t) => {
  await t.step("encrypt decrypt", () => {
    for (let i = 0; i < ITERATION_COUNT; i++) {
      const data = new Uint8Array(DATA_SIZE);
      const key = new Uint8Array(KEY_SIZE);
      const iv = new Uint8Array(IV_SIZE);

      crypto.getRandomValues(data);
      crypto.getRandomValues(key);
      crypto.getRandomValues(iv);

      const a = ige256Encrypt(data, key, iv);
      const b = ige256Decrypt(a, key, iv);

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

      const a = ige256Decrypt(data, key, iv);
      const b = ige256Encrypt(a, key, iv);

      assertEquals(b, data);
    }
  });
});
