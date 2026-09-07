import { expect, type Locator, type Page } from "@playwright/test";
import { stringify } from "yaml";

export async function openWorkflowForm(page: Page) {
  await page.getByRole("button", { name: "Create Workflow" }).click();
  const dialog = page.getByRole("dialog", {
    name: "Create workflow",
    exact: true,
  });
  await expect(dialog).toBeVisible();
  // Creation opens the required channel picker automatically.
  await expect(
    page.getByRole("listbox", { name: "Channel options" }),
  ).toBeVisible();
  await page.getByRole("option", { name: "general", exact: true }).click();
  await expect(
    dialog.getByRole("combobox", { name: "Channel", exact: true }),
  ).toContainText("general");
  return dialog;
}

export async function setWorkflowName(dialog: Locator, name: string) {
  await dialog
    .getByRole("button", { name: "Edit workflow name", exact: true })
    .click();
  await dialog
    .getByRole("textbox", { name: "Workflow name", exact: true })
    .fill(name);
  await dialog
    .getByRole("button", { name: "Save workflow name", exact: true })
    .click();
}

export async function addWorkflowMessageStep(page: Page, dialog: Locator) {
  await dialog.getByRole("button", { name: "Add step", exact: true }).click();
  await page
    .getByRole("menuitem", { name: "Send Message", exact: true })
    .click();
  // The outgoing trigger inspector has the same label during its exit
  // animation. Wait for the selected step's textarea before editing it.
  const message = dialog.locator("textarea#wf-step-0-text");
  await message.fill("Workflow fixture message");
  await expect(message).toHaveValue("Workflow fixture message");
}

export async function createWorkflow(
  page: Page,
  name: string,
  options?: {
    description?: string;
    enabled?: boolean;
    trigger?: string;
    stepCondition?: string;
    stepName?: string;
    stepTimeoutSecs?: string;
  },
) {
  const dialog = await openWorkflowForm(page);
  await setWorkflowName(dialog, name);
  await addWorkflowMessageStep(page, dialog);
  if (options) {
    // Advanced definition fields remain available through the YAML editor.
    await dialog.getByRole("tab", { name: "YAML", exact: true }).click();
    await dialog.getByRole("textbox", { name: "Workflow YAML" }).fill(
      stringify({
        name,
        description: options.description,
        enabled: options.enabled ?? true,
        trigger: { on: options.trigger ?? "message_posted" },
        steps: [
          {
            id: "step_1",
            action: "send_message",
            text: "Workflow fixture message",
            name: options.stepName,
            condition: options.stepCondition,
            timeout_secs: options.stepTimeoutSecs
              ? Number(options.stepTimeoutSecs)
              : undefined,
          },
        ],
      }),
    );
  }
  await dialog.getByTestId("workflow-dialog-primary-action").click();
  if (
    options?.enabled !== false &&
    (options?.trigger ?? "message_posted") !== "webhook"
  ) {
    const confirmation = page.getByTestId("workflow-activation-confirmation");
    await expect(confirmation).toBeVisible();
    await confirmation
      .getByRole("button", { name: "Turn on", exact: true })
      .click();
  }
  await expect(
    page.getByRole("dialog", {
      name: "Create workflow",
      exact: true,
      includeHidden: true,
    }),
  ).toHaveCount(0);
}
