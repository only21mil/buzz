import type * as React from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkBreaks from "remark-breaks";
import remarkGfm from "remark-gfm";

import remarkMessageLinks from "@/features/messages/lib/remarkMessageLinks";
import rehypeImageGallery from "@/shared/lib/rehypeImageGallery";
import rehypeSearchHighlight from "@/shared/lib/rehypeSearchHighlight";
import remarkChannelLinks from "@/shared/lib/remarkChannelLinks";
import remarkCustomEmoji, {
  type CustomEmoji,
} from "@/shared/lib/remarkCustomEmoji";
import remarkMentions from "@/shared/lib/remarkMentions";
import remarkSpoilers from "@/shared/lib/remarkSpoilers";

import { buzzDeepLinkUrlTransform } from "./utils";

/**
 * Parsed-markdown element cache.
 *
 * The message timeline's scroll container is keyed by channel id (see
 * MessageTimeline — required so TanStack Router's scroll restoration never
 * writes a stale scrollTop into a reused scroll node), so every channel
 * switch remounts every row and `React.memo` cannot carry the react-markdown
 * parse across the remount. react-markdown's `Markdown` is a plain
 * synchronous hook-free function, so its element tree is a pure function of
 * the parse inputs below and can be reused across mounts. Everything
 * per-mount (channels, imeta lookup, navigation callbacks) flows through
 * `MarkdownRuntimeContext`, read at render time — a cached element never
 * captures per-mount state. The `components` map passed in must be
 * module-stable and fully identified by `variant` (see
 * `getMarkdownComponents`) — the map itself is deliberately not part of the
 * cache key.
 *
 * Recency-ordered via Map insertion order. The count ceiling comfortably
 * covers two window-ceiling channels' worth of ordinary rows, while the
 * weight ceiling prevents a smaller set of large parses from retaining an
 * outsized share of a desktop renderer's heap.
 */
const MARKDOWN_NODE_CACHE_LIMIT = 1000;
/**
 * Conservative deterministic retention budget. JavaScript strings commonly
 * occupy two bytes per code unit; parsed markdown additionally retains a tree
 * of elements, props, and text. We charge each entry its key bytes, sixteen
 * bytes per source code unit for that tree, and 4 KiB of structural overhead.
 * This caps near-32K messages at roughly 28 entries while still allowing the
 * full 1000-entry ceiling for typical short chat messages.
 */
const MARKDOWN_NODE_CACHE_WEIGHT_LIMIT = 16 * 1024 * 1024;
const MARKDOWN_NODE_CACHE_ENTRY_OVERHEAD = 4 * 1024;
const MARKDOWN_NODE_CACHE_TREE_BYTES_PER_CODE_UNIT = 16;
/** Oversized messages (large agent pastes) bypass the cache: they rarely
 * repeat enough to benefit, and each entry would retain the full content in
 * both the key and the element tree. Mirrors the searchQuery bypass. */
const MARKDOWN_NODE_CACHE_MAX_CONTENT_LENGTH = 32_000;
type MarkdownNodeCacheEntry = {
  element: React.ReactElement;
  weight: number;
};

const markdownNodeCache = new Map<string, MarkdownNodeCacheEntry>();
let markdownNodeCacheWeight = 0;

/** Community switches swap relays; drop parses keyed against the old
 * community's mention/channel-name space (see `resetCommunityState`). */
export function clearMarkdownNodeCache() {
  markdownNodeCache.clear();
  markdownNodeCacheWeight = 0;
}

let markdownParseCount = 0;

/** Number of fresh react-markdown parses since app start (cache misses and
 * bypasses). Exposed through the e2e bridge so specs can assert that warm
 * channel switches are pure cache hits (zero fresh parses). */
export function getMarkdownParseCount(): number {
  return markdownParseCount;
}

/** Test-only observability for the cache's bounded-memory contract. */
export function getMarkdownNodeCacheSizeForTests(): number {
  return markdownNodeCache.size;
}

/** Test-only observability for exact weight-accounting assertions. */
export function getMarkdownNodeCacheWeightForTests(): number {
  return markdownNodeCacheWeight;
}

/** Test-only observability for the configured retention ceiling. */
export function getMarkdownNodeCacheWeightLimitForTests(): number {
  return MARKDOWN_NODE_CACHE_WEIGHT_LIMIT;
}

/** Inputs that fully determine the parsed element tree. `variant` identifies
 * the module-stable `components` map (see `getMarkdownComponents`); the two
 * must always come from the same call so they cannot drift apart. */
export type MarkdownParseInputs = {
  channelNames?: string[];
  components: Components;
  content: string;
  customEmoji?: CustomEmoji[];
  mentionNames?: string[];
  searchQuery?: string;
  variant: string;
};

/** Length-prefix a segment so no value can forge a boundary — an injective
 * encoding regardless of the bytes in relay-controlled names and URLs. */
function segment(value: string): string {
  return `${value.length}:${value}`;
}

function listSegment(values: readonly string[] | undefined): string {
  return segment(values?.map(segment).join("") ?? "");
}

function buildMarkdownElement(input: MarkdownParseInputs): React.ReactElement {
  markdownParseCount += 1;
  // biome-ignore lint/suspicious/noExplicitAny: PluggableList type not directly importable
  const rehypePlugins: any[] = [rehypeImageGallery];
  if (input.searchQuery && input.searchQuery.trim().length >= 2) {
    rehypePlugins.push([rehypeSearchHighlight, { query: input.searchQuery }]);
  }
  // Called as a plain function rather than rendered as <ReactMarkdown/>:
  // react-markdown's `Markdown` is synchronous and hook-free (the hook
  // variant is `MarkdownHooks`), so this returns the parsed element tree
  // directly, which is what lets it live in a module-level cache.
  return ReactMarkdown({
    children: input.content,
    components: input.components,
    remarkPlugins: [
      remarkGfm,
      remarkBreaks,
      remarkSpoilers,
      remarkMessageLinks,
      [remarkMentions, { mentionNames: input.mentionNames }],
      [remarkChannelLinks, { channelNames: input.channelNames }],
      [remarkCustomEmoji, { customEmoji: input.customEmoji }],
      // biome-ignore lint/suspicious/noExplicitAny: PluggableList type not directly importable
    ] as any[],
    rehypePlugins,
    urlTransform: buzzDeepLinkUrlTransform,
  });
}

function markdownNodeCacheEntryWeight(key: string, content: string): number {
  return (
    MARKDOWN_NODE_CACHE_ENTRY_OVERHEAD +
    key.length * 2 +
    content.length * MARKDOWN_NODE_CACHE_TREE_BYTES_PER_CODE_UNIT
  );
}

function deleteMarkdownNodeCacheEntry(key: string): boolean {
  const entry = markdownNodeCache.get(key);
  if (!entry) return false;
  markdownNodeCache.delete(key);
  markdownNodeCacheWeight -= entry.weight;
  return true;
}

function setMarkdownNodeCacheEntry(
  key: string,
  entry: MarkdownNodeCacheEntry,
): void {
  // Replacement is not expected on the normal miss path, but accounting it
  // here keeps this primitive correct if insertion policy changes later.
  deleteMarkdownNodeCacheEntry(key);
  markdownNodeCache.set(key, entry);
  markdownNodeCacheWeight += entry.weight;

  while (
    markdownNodeCache.size > MARKDOWN_NODE_CACHE_LIMIT ||
    markdownNodeCacheWeight > MARKDOWN_NODE_CACHE_WEIGHT_LIMIT
  ) {
    const oldest = markdownNodeCache.keys().next().value;
    if (oldest === undefined) break;
    deleteMarkdownNodeCacheEntry(oldest);
  }
}

/** Return the parsed element tree for the given inputs, reusing a cached
 * tree when an identical parse has been done before. See the module doc
 * comment for why this is safe. */
export function renderCachedMarkdown(
  input: MarkdownParseInputs,
): React.ReactElement {
  // Search highlighting is transient and query-specific: parse fresh rather
  // than churn the cache with per-query variants. Oversized content parses
  // fresh too — see MARKDOWN_NODE_CACHE_MAX_CONTENT_LENGTH.
  if (
    (input.searchQuery && input.searchQuery.trim().length >= 2) ||
    input.content.length > MARKDOWN_NODE_CACHE_MAX_CONTENT_LENGTH
  ) {
    return buildMarkdownElement(input);
  }
  // Everything that changes the parse output must be in the key. Arrays are
  // keyed by value, not identity — callers rebuild them across mounts. Every
  // field is length-prefixed, so relay-controlled values cannot collide two
  // distinct input tuples. Content is last and needs no prefix: everything
  // before it is self-delimiting.
  const key =
    segment(input.variant) +
    listSegment(input.mentionNames) +
    listSegment(input.channelNames) +
    listSegment(
      input.customEmoji?.map(
        (emoji) => segment(emoji.shortcode) + segment(emoji.url),
      ),
    ) +
    input.content;

  const hit = markdownNodeCache.get(key);
  if (hit) {
    // Replacing the entry refreshes Map insertion order and exercises the
    // same subtract-then-add accounting used by any future replacement.
    setMarkdownNodeCacheEntry(key, hit);
    return hit.element;
  }
  const element = buildMarkdownElement(input);
  const weight = markdownNodeCacheEntryWeight(key, input.content);
  // Pathological metadata can make the key itself exceed the whole budget
  // even when content is short. Parse it once, but preserve existing entries
  // instead of inserting an entry that would immediately evict everything.
  if (weight <= MARKDOWN_NODE_CACHE_WEIGHT_LIMIT) {
    setMarkdownNodeCacheEntry(key, { element, weight });
  }
  return element;
}
