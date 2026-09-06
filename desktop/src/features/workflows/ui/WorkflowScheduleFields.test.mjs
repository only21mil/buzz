import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { JSDOM } from "jsdom";
import {
  scheduleFormFromTrigger,
  scheduleTriggerFromForm,
  scheduleWeekdaysFromCronField,
} from "./workflowSchedule.ts";

const days = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
];
const names = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];

async function checkPicker(checkExpression) {
  const dom = new JSDOM("<!doctype html><html><body></body></html>");
  const originalWindow = globalThis.window;
  const originalDocument = globalThis.document;
  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  const { createElement: h, useState } = await import("react");
  const { render, fireEvent, cleanup } = await import("@testing-library/react");
  const { WorkflowScheduleFields } = await import(
    "./WorkflowScheduleFields.tsx"
  );
  let emitted;
  function Picker() {
    const [trigger, setTrigger] = useState({
      on: "schedule",
      cron: "0 9 * * *",
    });
    return h(WorkflowScheduleFields, {
      trigger,
      onUpdate: (next) => {
        emitted = next.cron;
        setTrigger(next);
      },
    });
  }
  try {
    for (const [index, day] of days.entries()) {
      const view = render(h(Picker));
      fireEvent.click(view.getByRole("radio", { name: "Weekly" }));
      assert.ok(view.getByRole("checkbox", { name: "Monday" }).checked);
      if (day !== "Monday") {
        fireEvent.click(view.getByRole("checkbox", { name: day }));
        fireEvent.click(view.getByRole("checkbox", { name: "Monday" }));
      }
      assert.equal(emitted, `0 9 * * ${index + 1}`);
      checkExpression(emitted, String(index + 1));
      cleanup();
      for (const field of [String(index + 1), names[index]]) {
        const cron = `0 9 * * ${field}`;
        const stored = render(
          h(WorkflowScheduleFields, {
            trigger: { on: "schedule", cron },
            onUpdate: () =>
              assert.fail("reading must not rewrite a stored schedule"),
          }),
        );
        assert.deepEqual(
          stored
            .getAllByRole("checkbox")
            .filter((input) => input.checked)
            .map((input) => input.getAttribute("aria-label")),
          [day],
        );
        const form = scheduleFormFromTrigger({ on: "schedule", cron });
        assert.equal(scheduleTriggerFromForm(form).cron, cron);
        assert.deepEqual(scheduleWeekdaysFromCronField(form.weekday), [
          String(index + 1),
        ]);
        checkExpression(cron, String(index + 1));
        cleanup();
      }
    }
    for (const [field, expected] of [
      ["1-7", "1,2,3,4,5,6,7"],
      ["MON-FRI", "2,3,4,5,6"],
      ["SUN,SAT", "1,7"],
    ]) {
      assert.equal(scheduleWeekdaysFromCronField(field).join(","), expected);
      checkExpression(`0 9 * * ${field}`, expected);
    }
  } finally {
    cleanup();
    dom.window.close();
    globalThis.window = originalWindow;
    globalThis.document = originalDocument;
  }
}

test("weekly picker emits and labels all seven runtime weekdays without rewriting stored expressions", async () => {
  await checkPicker(() => {});
});

test("mounted weekly selections and stored fields agree with the actual cron library", {
  skip: !process.env.WORKFLOW_CRON_PROBE,
}, async () => {
  await checkPicker((expression, expected) => {
    assert.equal(
      execFileSync(process.env.WORKFLOW_CRON_PROBE, [expression], {
        encoding: "utf8",
      }).trim(),
      expected,
      expression,
    );
  });
});
