import { expect, test } from "@playwright/test";
import { parse } from "yaml";

import { installMockBridge } from "../helpers/bridge";
import {
  addWorkflowMessageStep,
  createWorkflow,
  setWorkflowName,
} from "../helpers/workflows";

test.beforeEach(async ({ page }) => {
  await installMockBridge(page);
  await page.goto("/");
  await page.getByTestId("open-workflows-view").click();
});

test("name-first Channel selection and pane changes preserve the dirty draft; leaving still requires confirmation", async ({
  page,
}) => {
  await page.getByRole("button", { name: "Create Workflow" }).click();
  const editor = page.getByRole("dialog", {
    name: "Create workflow",
    exact: true,
  });
  await expect(
    page.getByRole("listbox", { name: "Channel options" }),
  ).toBeVisible();
  await setWorkflowName(editor, "channel_order_fixture");
  const channel = editor.getByRole("combobox", {
    name: "Channel",
    exact: true,
  });
  await channel.click();
  await expect(channel).toHaveAttribute("aria-expanded", "true");
  await page
    .getByRole("listbox", { name: "Channel options" })
    .getByRole("option", { name: "general", exact: true })
    .click();
  await expect(channel).toContainText("general");
  const discard = page.getByRole("alertdialog", { name: "Discard changes?" });
  await expect(discard).toHaveCount(0);
  await expect(editor).toContainText("channel_order_fixture");

  await addWorkflowMessageStep(page, editor);
  await expect(page).toHaveURL(/pane=step/);
  await editor.getByRole("button", { name: /^Trigger:/ }).click();
  await expect(page).toHaveURL(/pane=trigger/);
  await expect(discard).toHaveCount(0);
  await editor.getByRole("tab", { name: "YAML", exact: true }).click();
  const yaml = editor.getByRole("textbox", { name: "Workflow YAML" });
  const draft = await yaml.inputValue();
  expect(parse(draft).name).toBe("channel_order_fixture");
  expect(parse(draft).steps[0].text).toBe("Workflow fixture message");

  // Browser back changes the editor view on the same pathname.
  await page.evaluate(() => window.history.back());
  await expect(discard).toBeVisible();
  await discard
    .getByRole("button", { name: "Keep editing", exact: true })
    .click();
  await expect(discard).toHaveCount(0);
  await expect(yaml).toHaveValue(draft);
  await expect(channel).toContainText("general");
  await page.evaluate(() => window.history.back());
  await expect(discard).toBeVisible();
  await discard
    .getByRole("button", { name: "Discard changes", exact: true })
    .click();
  await expect(editor).toHaveCount(0);
  await expect(page).toHaveURL(/#\/workflows$/);
});

test("leaving a saved webhook still requires acknowledging the unrecoverable secret", async ({
  page,
}) => {
  await createWorkflow(page, "navigation_webhook_fixture", {
    trigger: "webhook",
  });
  const secret = page.getByRole("dialog", {
    name: "Webhook ready",
    exact: true,
  });
  await expect(secret).toBeVisible();
  const confirmation = page.getByRole("alertdialog", {
    name: "Continue without this secret?",
  });
  await page.evaluate(() => window.history.back());
  await expect(confirmation).toBeVisible();
  await confirmation
    .getByRole("button", { name: "Go back", exact: true })
    .click();
  await expect(confirmation).toHaveCount(0);
  await expect(secret).toBeVisible();
  await page.evaluate(() => window.history.back());
  await expect(confirmation).toBeVisible();
  await confirmation
    .getByRole("button", { name: "Continue", exact: true })
    .click();
  await expect(secret).toHaveCount(0);
  await expect(page).toHaveURL(/#\/workflows$/);
});
