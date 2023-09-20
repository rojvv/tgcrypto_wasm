import { ctr256, init } from "../dist/mod.ts";
import { assertEquals, decodeHex } from "./deps.ts";
import testdata from "../testdata/ctr.json" assert { type: "json" };

await init();

const DATA_SIZE = 64;
const KEY_SIZE = 32;
const IV_SIZE = 16;
const ITERATION_COUNT = 500;

Deno.test("expectancy", () => {
  const data = new Uint8Array(32);
  const key = new Uint8Array(32);
  const iv = new Uint8Array(16);
  const state = new Uint8Array(1);

  ctr256(data, key, iv, state);

  // deno-fmt-ignore
  const expectedIv = new Uint8Array([
    0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
    0, 0, 0, 2
  ]);
  const expectedState = new Uint8Array(1);
  // deno-fmt-ignore
  const expectedData = new Uint8Array([
    220, 149, 192, 120, 162,  64, 137,
    137, 173,  72, 162,  20, 146, 132,
    32, 135,  83,  15, 138, 251, 199,
    69,  54, 185, 169,  99, 180, 241,
    196, 203, 115, 139
  ]);

  assertEquals(iv, expectedIv);
  assertEquals(state, expectedState);
  assertEquals(data, expectedData);
});

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

      ctr256(data, key, new Uint8Array(iv), new Uint8Array(state));
      ctr256(data, key, new Uint8Array(iv), new Uint8Array(state));

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

      ctr256(data, key, new Uint8Array(iv), new Uint8Array(state));
      ctr256(data, key, new Uint8Array(iv), new Uint8Array(state));

      assertEquals(copy, data);
    }
  });
});

Deno.test("testdata", () => {
  for (
    const [key_, cases] of Object.entries(testdata) as [
      string,
      [
        { data: string; iv: string; state: string },
        { data: string; iv: string; state: string },
      ][],
    ][]
  ) {
    const key = decodeHex(key_);
    for (const [in_, expected] of cases) {
      const data = decodeHex(in_.data);
      const iv = decodeHex(in_.iv);
      const state = decodeHex(in_.state);
      ctr256(data, key, iv, state);
      assertEquals(data, decodeHex(expected.data));
      assertEquals(iv, decodeHex(expected.iv));
      assertEquals(state, decodeHex(expected.state));
    }
  }
});
