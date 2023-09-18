import { factorize, init } from "../dist/mod.ts";
import { assertEquals } from "./deps.ts";

await init();

Deno.test("factorize", async (t) => {
  await t.step("1", () => {
    const pq = factorize(1470626929934143021n);
    assertEquals(pq, [1206429347n, 1218991343n]);
  });

  await t.step("2", () => {
    const pq = factorize(1470626929934143021n);
    assertEquals(pq, [1206429347n, 1218991343n]);
  });
});
