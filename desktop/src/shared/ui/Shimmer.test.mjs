import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { JSDOM } from "jsdom";
import { Shimmer } from "./Shimmer.tsx";

test("shimmer overlay repeats the visible label but is hidden from accessibility", () => {
  const dom = new JSDOM(
    renderToStaticMarkup(React.createElement(Shimmer, null, "Working")),
  );
  const shimmer = dom.window.document.querySelector(".buzz-shimmer");
  const overlay = shimmer.querySelector(".buzz-shimmer-overlay");
  assert.equal(overlay.getAttribute("aria-hidden"), "true");
  assert.equal(overlay.textContent, "Working");
  overlay.remove();
  assert.equal(shimmer.textContent, "Working");
  dom.window.close();
});

test("reduced motion disables the shimmer overlay animation", () => {
  const css = readFileSync(
    new URL("../styles/globals/animations.css", import.meta.url),
    "utf8",
  );
  assert.match(
    css,
    /@media \(prefers-reduced-motion: reduce\)\s*\{\s*\.buzz-shimmer > \.buzz-shimmer-overlay\s*\{[^}]*animation: none;/,
  );
});
