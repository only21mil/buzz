// P01 fork contracts: workflow behaviors adopted from upstream, written against
// the fork editor UI (audit D3). New file. The fork-native workflows.spec.ts and
// workflow-navigation.spec.ts keep their coverage. This file restores the
// upstream regression behaviors those files dropped: card status toggle,
// deleting the open workflow, missing-route handling, and direct-route refresh.
// Revision-conflict paths (stale toggle, stale save, rejected status/delete)
// need mock revision support the fork bridge does not have yet. Those stay
// mapped as deferred for the relay/DB owners, not asserted here.
// All tests run service-free against the mock Tauri bridge.
import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";
import { createWorkflow } from "../helpers/workflows";

test.beforeEach(async ({ page }) => {
  await installMockBridge(page);
});

async function navigateToWorkflows(page: import("@playwright/test").Page) {
  await page.goto("/");
  await page.getByTestId("open-workflows-view").click();
  await expect(page).toHaveURL(/#\/workflows$/);
  await expect(page.getByTestId("workflows-view")).toBeVisible();
}

function workflowCard(page: import("@playwright/test").Page, name: string) {
  return page
    .locator('[data-testid^="workflow-card-"]')
    .filter({ hasText: name })
    .first();
}

test("card status toggle disables and re-enables with activation confirmation", async ({
  page,
}) => {
  const workflowName = `p01_toggle_${Date.now()}`;

  await navigateToWorkflows(page);
  await createWorkflow(page, workflowName);

  const card = workflowCard(page, workflowName);
  const disable = card.getByRole("switch", { name: "Disable workflow" });
  await expect(disable).toBeChecked();
  await disable.click();

  const enable = card.getByRole("switch", { name: "Enable workflow" });
  await expect(enable).not.toBeChecked();
  await enable.click();

  const confirmation = page.getByTestId("workflow-activation-confirmation");
  await expect(confirmation).toBeVisible();
  await confirmation.getByRole("button", { name: "Turn on" }).click();
  await expect(
    card.getByRole("switch", { name: "Disable workflow" }),
  ).toBeChecked();
});

test("deleting the open workflow closes its editor", async ({ page }) => {
  const workflowName = `p01_delete_open_${Date.now()}`;

  await navigateToWorkflows(page);
  await createWorkflow(page, workflowName);
  await page.getByRole("button", { name: `View ${workflowName}` }).click();

  const editor = page.getByRole("dialog", { name: "Edit workflow" });
  await expect(editor).toBeVisible();
  await editor.getByRole("button", { name: "Workflow actions" }).click();
  await page.getByRole("menuitem", { name: "Delete" }).click();
  await expect(page.getByRole("alertdialog")).toContainText(workflowName);
  await page.getByRole("button", { name: "Delete" }).click();

  await expect(editor).toHaveCount(0);
  await expect(page.getByTestId("workflows-view")).toBeVisible();
  await expect(workflowCard(page, workflowName)).toHaveCount(0);
});

test("missing workflow route shows an unavailable dialog with close", async ({
  page,
}) => {
  await navigateToWorkflows(page);
  await page.goto(`/#/workflows/does-not-exist?view=edit`);

  const dialog = page.getByRole("dialog", { name: "Workflow unavailable" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Retry" })).toBeVisible();
  await dialog.getByRole("button", { name: "Close" }).click();
  await expect(dialog).toHaveCount(0);
});

test("direct workflow routes survive refresh and invalid view opens detail", async ({
  page,
}) => {
  const workflowName = `p01_route_${Date.now()}`;
  await navigateToWorkflows(page);
  await createWorkflow(page, workflowName);

  await workflowCard(page, workflowName)
    .getByRole("button", { name: "Workflow actions" })
    .click();
  await page.getByRole("menuitem", { name: "Edit" }).click();
  const editor = page.getByRole("dialog", { name: "Edit workflow" });
  await expect(editor).toBeVisible();
  await expect(page).toHaveURL(/#\/workflows\/[^?/]+/);
  const workflowId = new URL(page.url()).hash.match(/workflows\/([^?/]+)/)?.[1];
  expect(workflowId).toBeTruthy();

  // In-page navigation keeps mock state: an invalid view still opens detail.
  await page.goto(`/#/workflows/${workflowId}?view=invalid`);
  const detail = page.getByRole("dialog", { name: "Edit workflow" });
  await expect(detail).toBeVisible();
  await expect(detail).toContainText(workflowName);

  // The create route needs no persisted workflow, so it survives reload.
  await page.goto("/#/workflows?view=create");

  await page.reload();
  await expect(
    page.getByRole("dialog", { name: "Create workflow", exact: true }),
  ).toBeVisible();
  await expect(page).toHaveURL(/#\/workflows\?view=create/);
});
