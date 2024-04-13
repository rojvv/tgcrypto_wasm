import {
  __getCtr256StateValues,
  __settCtr256StateState,
  createCtr256State,
  ctr256,
  destroyCtr256State,
  init,
} from "../dist/mod.ts";
import { assertEquals, decodeHex } from "./deps.ts";
import testdata from "../testdata/ctr.json" with { type: "json" };

await init();

const DATA_SIZE = 64;
const KEY_SIZE = 32;
const IV_SIZE = 16;
const ITERATION_COUNT = 500;

Deno.test("expectancy", () => {
  const data = new Uint8Array(32);
  const key = new Uint8Array(32);
  const iv = new Uint8Array(16);
  const state = createCtr256State(iv);

  ctr256(data, key, state);

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

  const { iv: iv_, state: state_ } = __getCtr256StateValues(state);
  assertEquals(iv_, expectedIv);
  assertEquals(state_, expectedState);
  assertEquals(data, expectedData);
});

Deno.test("random", async (t) => {
  await t.step("encrypt decrypt", () => {
    for (let i = 0; i < ITERATION_COUNT; i++) {
      const data = new Uint8Array(DATA_SIZE);
      const key = new Uint8Array(KEY_SIZE);
      const iv = new Uint8Array(IV_SIZE);
      crypto.getRandomValues(key);
      crypto.getRandomValues(iv);

      const estate = createCtr256State(iv);
      const dstate = createCtr256State(iv);

      crypto.getRandomValues(data);
      const copy = new Uint8Array(data);

      ctr256(data, key, createCtr256State(iv));
      ctr256(data, key, createCtr256State(iv));
      destroyCtr256State(estate);
      destroyCtr256State(dstate);

      assertEquals(copy, data);
    }
  });

  // await t.step("decrypt encrypt", () => {
  //   for (let i = 0; i < ITERATION_COUNT; i++) {
  //     const data = new Uint8Array(DATA_SIZE);

  //     const key = new Uint8Array(KEY_SIZE);
  //     const iv = new Uint8Array(IV_SIZE);
  //     crypto.getRandomValues(key);
  //     crypto.getRandomValues(iv);

  //     const estate = createCtr256State(iv);
  //     const dstate = createCtr256State(iv);

  //     crypto.getRandomValues(data);
  //     const copy = new Uint8Array(data);

  //     ctr256(data, key, estate);
  //     ctr256(data, key, dstate);
  //     destroyCtr256State(estate);
  //     destroyCtr256State(dstate);

  //     assertEquals(copy, data);
  //   }
  // });
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
      const state_ = decodeHex(in_.state);

      const state = createCtr256State(iv);
      __settCtr256StateState(state, state_);

      ctr256(data, key, state);
      assertEquals(data, decodeHex(expected.data));

      const { iv: iv_, state: state__ } = __getCtr256StateValues(state);
      assertEquals(iv_, decodeHex(expected.iv));
      assertEquals(state__, decodeHex(expected.state));
    }
  }
});
