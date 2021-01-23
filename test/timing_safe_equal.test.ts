import { describe, it, expect } from "@jest/globals";

import * as atota from "../src";

describe("atota", () => {
  it("can authenticate", async () => {
    let [pub, priv] = atota.generate_keypair();
    let auth = atota.authenticate(priv, 10);
    let verify = atota.verify(auth, pub, 15);

    expect(verify).toBe(true);
  });
});