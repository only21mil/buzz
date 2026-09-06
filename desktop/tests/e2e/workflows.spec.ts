import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";
import {
  addWorkflowMessageStep,
  createWorkflow,
  openWorkflowForm,
  setWorkflowName,
} from "../helpers/workflows";
import { parse } from "yaml";

test.beforeEach(async ({ page }) => {
  await installMockBridge(page);
});

async function navigateToWorkflows(page: import("@playwright/test").Page) {
  await page.goto("/");
  await page.getByTestId("open-workflows-view").click();
  await expect(page).toHaveURL(/#\/workflows$/);
  await expect(page.getByTestId("workflows-view")).toBeVisible();
}

test("navigates to workflows view and shows empty state", async ({ page }) => {
  await navigateToWorkflows(page);

  await expect(
    page
      .locator('[data-testid^="workflow-card-"]')
      .filter({ has: page.getByRole("button", { name: "Workflow actions" }) }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Create Workflow" }),
  ).toBeVisible();
});

test("creates a workflow via the form builder", async ({ page }) => {
  const workflowName = `test_workflow_${Date.now()}`;

  await navigateToWorkflows(page);
  await createWorkflow(page, workflowName);

  // Verify workflow appears in the list
  await expect(page.getByTestId("workflows-view")).toContainText(workflowName);
});

test("disables autocapitalization in the workflow form", async ({ page }) => {
  await navigateToWorkflows(page);

  const dialog = await openWorkflowForm(page);
  await dialog
    .getByRole("button", { name: "Edit workflow name", exact: true })
    .click();
  await expect(
    dialog.getByRole("textbox", { name: "Workflow name", exact: true }),
  ).toHaveAttribute("autocapitalize", "off");
  await dialog
    .getByRole("button", { name: "Save workflow name", exact: true })
    .click();
  await addWorkflowMessageStep(page, dialog);
  await dialog.getByRole("button", { name: "Step details" }).click();
  await expect(
    dialog.getByLabel("Name (optional)", { exact: true }),
  ).toHaveAttribute("autocapitalize", "off");
});

test("captures disabled diff workflows in the list UI", async ({ page }) => {
  const workflowName = `diff_workflow_${Date.now()}`;
  const description = "Watches diff events for src/ changes";

  await navigateToWorkflows(page);
  await createWorkflow(page, workflowName, {
    description,
    enabled: false,
    trigger: "diff_posted",
    stepName: "Notify reviewers",
    stepCondition: 'str_contains(trigger_text, "src/")',
    stepTimeoutSecs: "45",
  });

  const card = page
    .locator('[data-testid^="workflow-card-"]')
    .filter({ hasText: workflowName })
    .first();
  await expect(card).toContainText(workflowName);
  await expect(card.getByTestId("workflow-card-semantic-label")).toContainText(
    /diff/i,
  );
  await expect(
    card.getByRole("switch", { name: "Enable workflow" }),
  ).not.toBeChecked();
  await card.getByRole("button", { name: "Workflow actions" }).click();
  await page.getByRole("menuitem", { name: "Edit", exact: true }).click();
  const editor = page.getByRole("dialog", {
    name: "Edit workflow",
    exact: true,
  });
  await editor.getByRole("tab", { name: "YAML", exact: true }).click();
  const definition: unknown = parse(
    await editor.getByRole("textbox", { name: "Workflow YAML" }).inputValue(),
  );
  expect(definition).toMatchObject({
    description,
    enabled: false,
    trigger: { on: "diff_posted" },
    steps: [
      {
        name: "Notify reviewers",
        condition: 'str_contains(trigger_text, "src/")',
        timeout_secs: 45,
      },
    ],
  });
});

test("shows the webhook secret dialog after saving a webhook workflow", async ({
  page,
}) => {
  const workflowName = `webhook_workflow_${Date.now()}`;

  await navigateToWorkflows(page);
  await createWorkflow(page, workflowName, {
    trigger: "webhook",
  });

  await expect(page.getByText("Webhook ready")).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy URL" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy Secret" })).toBeVisible();

  await page
    .getByRole("dialog", { name: "Webhook ready", exact: true })
    .getByRole("button", { name: "Continue", exact: true })
    .click();
  const confirmation = page.getByRole("alertdialog", {
    name: "Continue without this secret?",
  });
  await expect(confirmation).toBeVisible();
  await confirmation
    .getByRole("button", { name: "Continue", exact: true })
    .click();
  await expect(
    page.getByRole("dialog", {
      name: "Webhook ready",
      exact: true,
      includeHidden: true,
    }),
  ).toHaveCount(0);
});

test("edits an existing workflow", async ({ page }) => {
  const originalName = `edit_test_${Date.now()}`;
  const updatedName = `${originalName}_updated`;

  await navigateToWorkflows(page);
  await createWorkflow(page, originalName);

  // Verify it exists
  await expect(page.getByTestId("workflows-view")).toContainText(originalName);

  // Open the dropdown menu and click Edit
  await page.getByRole("button", { name: "Workflow actions" }).first().click();
  await page.getByRole("menuitem", { name: "Edit" }).click();

  const dialog = page.getByRole("dialog", {
    name: "Edit workflow",
    exact: true,
  });
  await expect(dialog).toBeVisible();
  await setWorkflowName(dialog, updatedName);
  await dialog.getByTestId("workflow-dialog-primary-action").click();
  await expect(dialog).toHaveCount(0);

  // Verify the updated name appears
  await expect(page.getByTestId("workflows-view")).toContainText(updatedName);
});

test("duplicates a workflow", async ({ page }) => {
  const originalName = `dup_test_${Date.now()}`;

  await navigateToWorkflows(page);
  await createWorkflow(page, originalName);

  // Open the dropdown menu and click Duplicate
  await page.getByRole("button", { name: "Workflow actions" }).first().click();
  await page.getByRole("menuitem", { name: "Duplicate" }).click();

  const dialog = page.getByRole("dialog", {
    name: "Duplicate workflow",
    exact: true,
  });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText(`${originalName} (copy)`);
  await dialog.getByRole("combobox", { name: "Channel", exact: true }).click();
  await page.getByRole("option", { name: "general", exact: true }).click();
  await dialog.getByTestId("workflow-dialog-primary-action").click();
  await page
    .getByTestId("workflow-activation-confirmation")
    .getByRole("button", { name: "Turn on", exact: true })
    .click();
  await expect(
    page.getByRole("dialog", {
      name: "Duplicate workflow",
      exact: true,
      includeHidden: true,
    }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: `View ${originalName}`, exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", {
      name: `View ${originalName} (copy)`,
      exact: true,
    }),
  ).toBeVisible();
});

test("deletes a workflow with confirmation", async ({ page }) => {
  const workflowName = `delete_test_${Date.now()}`;

  await navigateToWorkflows(page);
  await createWorkflow(page, workflowName);

  // Verify it exists
  await expect(page.getByTestId("workflows-view")).toContainText(workflowName);

  // Open the dropdown menu and click Delete
  await page.getByRole("button", { name: "Workflow actions" }).first().click();
  await page.getByRole("menuitem", { name: "Delete" }).click();

  // Confirmation dialog should appear with workflow name
  await expect(page.getByRole("alertdialog")).toBeVisible();
  await expect(page.getByRole("alertdialog")).toContainText(workflowName);

  // Confirm deletion
  await page.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("alertdialog")).not.toBeVisible();

  // Verify workflow is gone — back to empty state
  await expect(
    page
      .locator('[data-testid^="workflow-card-"]')
      .filter({ has: page.getByRole("button", { name: "Workflow actions" }) }),
  ).toHaveCount(0);
});

test("triggers a workflow from its editor and displays the accepted run in history", async ({
  page,
}) => {
  const workflowName = `trigger_test_${Date.now()}`;
  await navigateToWorkflows(page);
  await createWorkflow(page, workflowName);
  await page
    .getByRole("button", { name: `View ${workflowName}`, exact: true })
    .click();
  const editor = page.getByRole("dialog", {
    name: "Edit workflow",
    exact: true,
  });
  await expect(editor).toBeVisible();
  await editor
    .getByRole("button", { name: "Workflow actions", exact: true })
    .click();
  await page.getByRole("menuitem", { name: "Trigger", exact: true }).click();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          window.__BUZZ_E2E_COMMAND_LOG__?.filter(
            (entry) => entry.command === "trigger_workflow",
          ).length ?? 0,
      ),
    )
    .toBe(1);
  await editor
    .getByRole("button", { name: "Run history", exact: true })
    .click();
  const history = page.getByTestId("workflow-history-dropdown");
  await expect(history).toBeVisible();
  const run = history.getByRole("button", { name: /mock-run.*completed/ });
  await expect(run).toBeVisible();
  await run.click();
  await expect(run).toContainText(/mock-run-\d+/);
  await expect(history).toContainText("Workflow fixture message");
});
