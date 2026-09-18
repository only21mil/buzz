import { expect, test } from "@playwright/test";

const PROBE_DISABLED = {
  status: 200,
  contentType: "application/json",
  body: JSON.stringify({ auth: "disabled", canAct: false, canStaff: false }),
};

test("disabled mode loads with no extension and no credential", async ({
  page,
}) => {
  const credentials: Array<string | null> = [];
  await page.route("**/api/admin/v1/probe", (route) =>
    route.fulfill(PROBE_DISABLED),
  );
  await page.route("**/api/admin/v1/reports?**", async (route) => {
    credentials.push(await route.request().headerValue("authorization"));
    return route.fulfill({ contentType: "application/json", body: "[]" });
  });
  await page.goto("/reports");
  await expect(
    page.getByRole("heading", { name: "Open reports" }),
  ).toBeVisible();
  expect(credentials.length).toBeGreaterThan(0);
  expect(credentials.every((value) => value === null)).toBe(true);
});

test("nip98 mode without an extension shows the install screen", async ({
  page,
}) => {
  await page.route("**/api/admin/v1/probe", (route) =>
    route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "unauthorized", message: "credential required" },
      }),
    }),
  );
  await page.goto("/reports");
  await expect(
    page.getByRole("heading", { name: "Nostr extension required" }),
  ).toBeVisible();
});

test("nip98 mode signs each request through the extension", async ({
  page,
}) => {
  await page.addInitScript(() => {
    (window as unknown as Record<string, unknown>).nostr = {
      signEvent: async (event: Record<string, unknown>) => ({
        ...event,
        id: "00".repeat(32),
        pubkey: "11".repeat(32),
        sig: "22".repeat(64),
      }),
    };
  });
  const credentials: string[] = [];
  await page.route("**/api/admin/v1/probe", (route) =>
    route.fulfill({ status: 401, body: "{}" }),
  );
  await page.route("**/api/admin/v1/reports?**", async (route) => {
    credentials.push(
      (await route.request().headerValue("authorization")) ?? "",
    );
    return route.fulfill({ contentType: "application/json", body: "[]" });
  });
  await page.goto("/reports");
  await expect(
    page.getByRole("heading", { name: "Open reports" }),
  ).toBeVisible();
  expect(credentials.length).toBeGreaterThan(0);
  for (const credential of credentials) {
    expect(credential.startsWith("Nostr ")).toBe(true);
    const event = JSON.parse(
      Buffer.from(credential.slice("Nostr ".length), "base64").toString("utf8"),
    );
    expect(event.kind).toBe(27235);
    const tags = new Map(event.tags.map((tag: string[]) => [tag[0], tag[1]]));
    expect(tags.get("method")).toBe("GET");
    expect(tags.get("u")).toMatch(
      /^http:\/\/127\.0\.0\.1:4174\/api\/admin\/v1\/reports/,
    );
    expect(typeof tags.get("nonce")).toBe("string");
  }
  const nonces = new Set(
    credentials.map((credential) => {
      const event = JSON.parse(
        Buffer.from(credential.slice("Nostr ".length), "base64").toString(
          "utf8",
        ),
      );
      return new Map(event.tags).get("nonce");
    }),
  );
  expect(nonces.size).toBe(credentials.length);
});

test("a rejected credential retries once, then shows sign-in expired", async ({
  page,
}) => {
  await page.addInitScript(() => {
    (window as unknown as Record<string, unknown>).nostr = {
      signEvent: async (event: Record<string, unknown>) => ({
        ...event,
        id: "00".repeat(32),
        pubkey: "11".repeat(32),
        sig: "22".repeat(64),
      }),
    };
  });
  let requests = 0;
  await page.route("**/api/admin/v1/probe", (route) =>
    route.fulfill({ status: 401, body: "{}" }),
  );
  await page.route("**/api/admin/v1/reports?**", (route) => {
    requests += 1;
    return route.fulfill({ status: 401, body: "{}" });
  });
  await page.goto("/reports");
  await expect(
    page.getByRole("heading", { name: "Sign-in expired" }),
  ).toBeVisible();
  expect(requests).toBe(2);
});
