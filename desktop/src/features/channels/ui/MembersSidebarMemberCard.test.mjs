import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("./MembersSidebarMemberCard.tsx", import.meta.url),
  "utf8",
);

test("member action trigger stays in the accessibility tree before hover", () => {
  const trigger = source.match(
    /<DropdownMenuTrigger asChild>([\s\S]*?)<\/DropdownMenuTrigger>/,
  )?.[1];

  assert.ok(trigger, "member action trigger must render");
  assert.match(trigger, /aria-label={`Actions for \${memberLabel}`}/);
  assert.doesNotMatch(trigger, /\binvisible\b/);
  assert.match(trigger, /focus-visible:opacity-100/);
});
