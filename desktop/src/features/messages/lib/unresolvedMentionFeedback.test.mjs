import assert from "node:assert/strict";
import test from "node:test";

import { unresolvedMentionError } from "./unresolvedMentionFeedback.ts";

test("blocks a typed mention that has no recipient binding", () => {
  assert.equal(
    unresolvedMentionError("@sats claude code-r please review", []),
    "That @mention is not linked to a member. Choose a recipient from the mention picker or remove the @ before sending.",
  );
});

test("accepts a resolved multi-word mention at the same sigil", () => {
  assert.equal(
    unresolvedMentionError("@Sats Claude Code-R please review", [
      "Sats Claude Code-R",
    ]),
    null,
  );
});

test("ignores email addresses and mentions inside Markdown code", () => {
  assert.equal(
    unresolvedMentionError(
      "Email sats@example.com or run `buzz send @sats`\n```sh\nbuzz send @other\n```",
      [],
    ),
    null,
  );
});

test("checks every mention when an earlier mention is resolved", () => {
  assert.match(
    unresolvedMentionError("Ask @Alice, then @missing", ["Alice"]),
    /not linked to a member/,
  );
});

test("blocks an unresolved mention inside spoiler markers", () => {
  assert.match(unresolvedMentionError("||@missing||", []), /not linked/);
});
