import assert from "node:assert/strict";
import { after, afterEach, test } from "node:test";
import { JSDOM } from "jsdom";

import { visibleImageGalleryForTrigger } from "./imageLightbox.ts";

const dom = new JSDOM("<!doctype html><body></body>");
Object.assign(globalThis, { window: dom.window });
// JSDOM does not implement CSS transitions or layout. Browser coverage pauses
// the actual spoiler transition; this fixture checks gallery boundary decisions.
class ControlledKeyframeEffect {
  constructor(targetOpacity) {
    this.targetOpacity = targetOpacity;
  }
  getKeyframes() {
    return [{ opacity: 0 }, { opacity: this.targetOpacity }];
  }
}
class ControlledTransition {
  transitionProperty = "opacity";
  constructor(targetOpacity) {
    this.effect = new ControlledKeyframeEffect(targetOpacity);
  }
}
Object.assign(globalThis, {
  CSSTransition: ControlledTransition,
  KeyframeEffect: ControlledKeyframeEffect,
});
afterEach(() => dom.window.document.body.replaceChildren());
after(() => dom.window.close());

function fixture() {
  const scope = dom.window.document.createElement("div");
  dom.window.document.body.append(scope);
  function addImage(parent, source) {
    const trigger = dom.window.document.createElement("button");
    trigger.dataset.imageLightboxTrigger = "";
    trigger.dataset.imageLightboxResolvedSrc = source;
    trigger.style.opacity = "1";
    const image = dom.window.document.createElement("img");
    image.style.opacity = "1";
    image.getBoundingClientRect = () => ({
      x: 0,
      y: 0,
      left: 0,
      top: 0,
      width: 80,
      height: 60,
    });
    image.getAnimations = trigger.getAnimations = () => [];
    trigger.append(image);
    parent.append(trigger);
    return { trigger, image };
  }
  const current = addImage(scope, "https://example.com/current.png");
  const spoiler = dom.window.document.createElement("span");
  spoiler.className = "buzz-spoiler";
  spoiler.dataset.spoiler = "";
  spoiler.dataset.revealed = "true";
  scope.append(spoiler);
  const revealed = addImage(spoiler, "https://example.com/revealed.png");
  const fallback = {
    resolvedSrc: current.trigger.dataset.imageLightboxResolvedSrc,
  };
  const gallery = (root = scope) =>
    visibleImageGalleryForTrigger(current.trigger, fallback, root);
  function fade(element, targetOpacity = 1) {
    element.style.opacity = "0";
    element.getAnimations = () => [new ControlledTransition(targetOpacity)];
  }
  return {
    scope,
    current,
    spoiler,
    revealed,
    fallback,
    gallery,
    fade,
    addImage,
  };
}

for (const target of ["trigger", "image"]) {
  test(`a revealed spoiler's ${target} joins the gallery at the initial fade frame`, () => {
    const f = fixture();
    f.fade(f.revealed[target]);
    const result = f.gallery();
    assert.equal(result.galleryIndex, 0);
    assert.deepEqual(
      result.galleryItems?.map((item) => item.resolvedSrc),
      ["https://example.com/current.png", "https://example.com/revealed.png"],
    );
  });
}

test("an unrevealed spoiler remains excluded even with a fade toward visibility", () => {
  const f = fixture();
  f.spoiler.dataset.revealed = "false";
  f.fade(f.revealed.image);
  assert.equal(f.gallery().galleryItems, undefined);
});

test("a revealed inner spoiler stays excluded beneath a hidden outer spoiler", () => {
  const f = fixture();
  const outer = f.spoiler.cloneNode(false);
  outer.dataset.revealed = "false";
  f.scope.append(outer);
  outer.append(f.spoiler);
  f.fade(f.revealed.image);
  assert.equal(f.gallery().galleryItems, undefined);
});

test("stationary transparency and transitions toward zero stay excluded", () => {
  const f = fixture();
  f.revealed.image.style.opacity = "0";
  assert.equal(f.gallery().galleryItems, undefined);
  f.fade(f.revealed.image, 0);
  assert.equal(f.gallery().galleryItems, undefined);
  f.fade(f.revealed.image);
  f.spoiler.removeAttribute("data-spoiler");
  assert.equal(f.gallery().galleryItems, undefined);
});

test("a reveal fade never bypasses display, visibility, geometry or source checks", () => {
  for (const exclude of [
    (f) => {
      f.revealed.trigger.style.display = "none";
    },
    (f) => {
      f.revealed.image.style.visibility = "hidden";
    },
    (f) => {
      f.revealed.image.getBoundingClientRect = () => ({ width: 0, height: 60 });
    },
    (f) => {
      delete f.revealed.trigger.dataset.imageLightboxResolvedSrc;
    },
  ]) {
    const f = fixture();
    f.fade(f.revealed.image);
    exclude(f);
    assert.equal(f.gallery().galleryItems, undefined);
  }
});

test("gallery membership stays in the connected source scope", () => {
  const f = fixture();
  f.spoiler.remove();
  f.addImage(dom.window.document.body, "https://example.com/outside.png");
  assert.equal(f.gallery().galleryItems, undefined);
  f.scope.remove();
  assert.equal(f.gallery().galleryItems, undefined);
  assert.equal(f.gallery().galleryIndex, 0);
});
