import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { deferredIdentity } from "./deferredIdentity.ts";
import { startBrowserShell } from "./startup.ts";
import {
  dispatch,
  initializePal,
  register,
  resetRegistryForTests,
} from "./registry.ts";
afterEach(resetRegistryForTests);

test("shell renders before unlock and signing waits for the same promise", async () => {
  const waterfall = [];
  let unlock;
  const identity = new Promise((resolve) => {
    unlock = resolve;
  });
  let signatures = 0;
  const boot = startBrowserShell(
    () => waterfall.push("shell"),
    () =>
      initializePal(async () => {
        waterfall.push("unlock-start");
        await identity;
        waterfall.push("unlock-end");
        register("sign_event", () => {
          signatures += 1;
          return "signed";
        });
      }),
    () => waterfall.push("app"),
  );
  const signed = dispatch("sign_event");
  await Promise.resolve();
  assert.deepEqual(waterfall, ["shell", "unlock-start"]);
  assert.equal(signatures, 0);
  unlock();
  await boot;
  assert.equal(await signed, "signed");
  assert.deepEqual(waterfall, ["shell", "unlock-start", "unlock-end", "app"]);
});

test("unlock failure keeps protected content gated and signing fails closed", async () => {
  let rendered = false;
  register("sign_event", () => assert.fail("must never sign"));
  const boot = startBrowserShell(
    () => {},
    () =>
      initializePal(async () => {
        throw new Error("storage unavailable");
      }),
    () => {
      rendered = true;
    },
  );
  await assert.rejects(boot, /Browser identity initialization failed/);
  await assert.rejects(
    dispatch("sign_event"),
    /Browser identity initialization failed/,
  );
  assert.equal(rendered, false);
});

test("PAL surfaces register synchronously while their identity remains locked", async () => {
  let unlock;
  const pending = deferredIdentity(
    new Promise((resolve) => {
      unlock = resolve;
    }),
  );
  let registered = false;
  const ready = initializePal(async () => {
    register("get_identity", () => pending.identity.identity());
    register("sign_event", () => pending.identity.sign({ kind: 9 }));
    registered = true;
    await pending.ready;
  });
  assert.equal(registered, true);
  assert.throws(() => pending.identity.sign({}), /not ready/);
  const command = dispatch("sign_event");
  unlock({
    identity: () => ({ pubkey: "public" }),
    sign() {
      return this.identity().pubkey;
    },
  });
  await ready;
  assert.equal(await command, "public");
});
