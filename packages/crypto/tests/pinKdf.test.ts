/**
 * pinKdf.test.ts
 * Verifies that two clients deriving a key from the same PIN get identical
 * results, and that different PINs produce distinct keys.
 */

import { derivePinKey } from "../src/pinKdf.js";

describe("derivePinKey", () => {
  it("produces a 32-byte key", async () => {
    const key = await derivePinKey("123456");
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.byteLength).toBe(32);
  });

  it("is deterministic — same PIN produces same key on both sides", async () => {
    const pin = "047291";
    const keyA = await derivePinKey(pin);
    const keyB = await derivePinKey(pin);
    expect(keyA).toEqual(keyB);
  });

  it("different PINs produce different keys", async () => {
    const keyA = await derivePinKey("000001");
    const keyB = await derivePinKey("000002");
    expect(keyA).not.toEqual(keyB);
  });

  it("zero-padded PIN is distinct from unpadded", async () => {
    const keyA = await derivePinKey("001234");
    const keyB = await derivePinKey("1234");
    expect(keyA).not.toEqual(keyB);
  });
});
