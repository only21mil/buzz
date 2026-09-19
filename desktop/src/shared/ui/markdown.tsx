import { parseEntityLink } from "@/shared/lib/entityLink";
import { parseChannelLink } from "@/features/messages/lib/channelLink";
import {
  AuthoredDeepLinkAnchor,
  ChannelDeepLinkAnchor,
  MarkdownChannelDeepLink,
  MarkdownChannelReference,
} from "./markdown/ChannelDeepLink";
import { isAudioAttachment } from "@/features/messages/lib/audioAttachment";
import { renderAudioMessageAttachment } from "@/features/messages/ui/AudioMessageAttachment";
import { isRelayDownloadable } from "./markdown/mediaEntry";
import { createMarkdownMention } from "./markdown/MarkdownMention";
import * as React from "react";

import type { Components } from "react-markdown";

import { toast } from "sonner";

import { useAppNavigation } from "@/app/navigation/useAppNavigation";
import { requestOpenSnapshotImport } from "@/features/agents/openSnapshotImportFromUrlEvent";
import {
  parseMessageLink,
  resolveMessageLinkRenderTarget,
  type ParsedMessageLink,
} from "@/features/messages/lib/messageLink";
import { invokeTauri } from "@/shared/api/tauri";
import { useChannelNavigation } from "@/shared/context/ChannelNavigationContext";
import { cn } from "@/shared/lib/cn";
import { parseSupportedLinkPreview } from "@/shared/lib/linkPreview";
import { parseLinkPreviewSnapshots } from "@/shared/lib/linkPreviewSnapshot";
import { rewriteRelayUrl } from "@/shared/lib/mediaUrl";
import { useRelayOrigin } from "@/shared/lib/useRelayOrigin";
import { AttachmentGroup } from "@/shared/ui/attachment";
import { ConfigNudgeCard } from "@/shared/ui/config-nudge-attachment";
import { LinkPreviewList } from "@/shared/ui/link-preview-list";
import { useSmoothCorners } from "@/shared/ui/smoothCorners";
import {
  computeConfigNudge,
  selectProseOrNudge,
} from "@/shared/lib/computeConfigNudge";
import {
  INLINE_CODE_CHIP_CLASS,
  MESSAGE_MARKDOWN_CLASS,
} from "@/shared/ui/mentionChip";

import {
  classifyChildren,
  hasBlockMedia,
  isImageOnlyParagraph,
  shallowArrayEqual,
  shallowRecordEqual,
} from "./markdownUtils";
import {
  CODE_BLOCK_CLASS,
  extractLanguage,
  MarkdownCodeBlock,
  SyntaxHighlightedCode,
} from "./markdown/CodeBlock";
import {
  EntityLinkAnchor,
  useEntityCardOpenHandlers,
  useOpenEntityLink,
} from "./markdown/entityLinks";
import { ExternalLinkAnchor } from "./markdown/ExternalLinkAnchor";
import { FileCard } from "./markdown/FileCard";
import { InlineEmojiPopover } from "./markdown/InlineEmojiPopover";
import { createLinkPreviewImageLightbox } from "./markdown/LinkPreviewImageLightbox";
import { MarkdownInput } from "./markdown/MarkdownInput";
import {
  MediaContextMenu,
  type MediaContextMenuPosition,
  useDismissMediaContextMenu,
} from "./markdown/MediaContextMenu";
import { isVideoMedia } from "./markdown/mediaEntry";
import {
  type ImageGalleryItem,
  type ImageLightboxBox,
  type ImageLightboxCornerRadii,
  imageLightboxBoxFromRect,
  imageLightboxCornerRadiiFromElement,
  imageLightboxSourceScopeForTrigger,
  visibleImageGalleryForTrigger,
} from "./markdown/imageLightbox";
import { MarkdownTable } from "./markdown/MarkdownTable";
import { ProgressiveImage } from "./markdown/ProgressiveImage";
import { MessageLinkPill } from "./markdown/MessageLinkPill";
import { renderCachedMarkdown } from "./markdown/nodeCache";
import {
  MarkdownRuntimeContext,
  useMarkdownRuntime,
} from "./markdown/runtimeContext";
import { AgentSnapshotCard } from "./markdown/AgentSnapshotCard";
import { resolveFileCard, resolveSnapshotCard } from "./markdownFileCard";
import type { MarkdownProps, MarkdownRuntime } from "./markdown/types";
import { SpoilerInline } from "./markdown/SpoilerInline";
import {
  imageReserveStyle,
  isInsideHiddenSpoiler,
  getReactNodeText,
  rememberDecodedImageDimensions,
  useFrozenImageReserve,
  useStableArray,
} from "./markdown/utils";
import {
  MarkdownVideoPlayer,
  VideoReviewMarkdownContext,
} from "./markdown/MarkdownVideoPlayer";

import { ImageZoomOverlay } from "./markdown/ImageZoomOverlay";

type ImageBlockProps = {
  alt: string | undefined;
  dim?: string;
  resolvedSrc: string | undefined;
  src: string | undefined;
  thumbSrc?: string;
};

export const LinkPreviewImageLightbox =
  createLinkPreviewImageLightbox(ImageZoomOverlay);

/**
 * Inline image embed with click-to-zoom lightbox and right-click download.
 *
 * IMPORTANT: the trigger is a plain button that we control ourselves — not
 * Radix's `<Trigger asChild>` cloning onto a wrapper. An earlier version used
 * that pattern and caused a 1-2px layout reflow in the surrounding message
 * body on hover. Keeping the trigger stable and managing the lightbox via
 * React state avoids that repaint.
 */
function ImageBlock({ alt, dim, resolvedSrc, src, thumbSrc }: ImageBlockProps) {
  const [lightboxState, setLightboxState] = React.useState<{
    galleryIndex: number;
    galleryItems?: ImageGalleryItem[];
    sourceBox: ImageLightboxBox;
    sourceCornerRadii: ImageLightboxCornerRadii;
    sourceScope: Element | null;
  } | null>(null);
  const [isHiddenInSpoiler, setIsHiddenInSpoiler] = React.useState(false);
  const [menu, setMenu] = React.useState<MediaContextMenuPosition | null>(null);
  const inlineImageRef = React.useRef<HTMLImageElement | null>(null);
  const thumbnailImageRef = React.useRef<HTMLImageElement | null>(null);
  const triggerRef = React.useRef<HTMLButtonElement | null>(null);
  useSmoothCorners(inlineImageRef);
  useSmoothCorners(thumbnailImageRef);

  const [spoilerMediaSize, setSpoilerMediaSize] = React.useState<{
    height: number;
    src: string;
    width: number;
  } | null>(null);

  const updateSpoilerMediaSize = React.useCallback(
    (image: HTMLImageElement) => {
      const { naturalHeight, naturalWidth } = image;
      if (naturalHeight <= 0 || naturalWidth <= 0) return;

      const maxWidth = 384;
      const maxHeight = 256;
      const scale = Math.min(
        1,
        maxWidth / naturalWidth,
        maxHeight / naturalHeight,
      );
      setSpoilerMediaSize({
        height: Math.max(1, Math.round(naturalHeight * scale)),
        src: resolvedSrc ?? image.currentSrc,
        width: Math.max(1, Math.round(naturalWidth * scale)),
      });
    },
    [resolvedSrc],
  );

  const handleImageLoad = React.useCallback(
    (image: HTMLImageElement) => {
      rememberDecodedImageDimensions(
        resolvedSrc,
        image.naturalWidth,
        image.naturalHeight,
      );
      updateSpoilerMediaSize(image);
    },
    [resolvedSrc, updateSpoilerMediaSize],
  );

  const { intrinsicDimensions, useFixedReserveBox } = useFrozenImageReserve(
    dim,
    resolvedSrc,
  );

  const currentSpoilerMediaSize =
    spoilerMediaSize?.src === resolvedSrc ? spoilerMediaSize : null;
  const hiddenSpoilerMediaSize = isHiddenInSpoiler
    ? currentSpoilerMediaSize
    : null;

  const spoilerMediaStyle = imageReserveStyle({
    hiddenSpoilerMediaSize,
    intrinsicDimensions,
    useFixedReserveBox,
  });

  React.useLayoutEffect(() => {
    const trigger = triggerRef.current;
    if (!trigger) return;

    const updateHiddenState = () => {
      setIsHiddenInSpoiler(isInsideHiddenSpoiler(trigger));
    };

    updateHiddenState();

    const spoiler = trigger.closest(".buzz-spoiler[data-spoiler]");
    if (!spoiler) return;

    const observer = new MutationObserver(updateHiddenState);
    observer.observe(spoiler, {
      attributeFilter: ["data-revealed"],
      attributes: true,
    });

    return () => observer.disconnect();
  }, []);

  const closeMenu = React.useCallback(() => setMenu(null), []);
  useDismissMediaContextMenu(Boolean(menu), closeMenu);

  const handleContextMenu = (e: React.MouseEvent) => {
    e.preventDefault();
    if (isInsideHiddenSpoiler(e.currentTarget)) return;
    e.stopPropagation();
    e.nativeEvent.stopImmediatePropagation();
    setMenu({ x: e.clientX, y: e.clientY });
  };

  const openLightbox = React.useCallback(
    (image: HTMLImageElement) => {
      if (!resolvedSrc || isInsideHiddenSpoiler(image)) {
        return;
      }

      const rect = image.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) {
        return;
      }

      setMenu(null);
      const sourceBox = imageLightboxBoxFromRect(rect);
      const sourceCornerRadii = imageLightboxCornerRadiiFromElement(image);
      const sourceScope = triggerRef.current
        ? imageLightboxSourceScopeForTrigger(triggerRef.current)
        : null;
      const gallery = triggerRef.current
        ? visibleImageGalleryForTrigger(
            triggerRef.current,
            {
              alt,
              dim,
              resolvedSrc,
              src,
              thumbnailBox: sourceBox,
              thumbnailCornerRadii: sourceCornerRadii,
            },
            sourceScope,
          )
        : { galleryIndex: 0, galleryItems: undefined };
      setLightboxState({
        galleryIndex: gallery.galleryIndex,
        galleryItems: gallery.galleryItems,
        sourceBox,
        sourceCornerRadii,
        sourceScope,
      });
    },
    [alt, dim, resolvedSrc, src],
  );

  const handleImageTriggerClick = () => {
    if (inlineImageRef.current) {
      openLightbox(inlineImageRef.current);
    }
  };

  const handleCopyImage = React.useCallback((copySrc: string | undefined) => {
    setMenu(null);
    if (!copySrc) return;
    invokeTauri("copy_image_to_clipboard", { url: copySrc })
      .then(() => {
        toast.success("Copied to clipboard");
      })
      .catch((err: unknown) => {
        const msg = err instanceof Error ? err.message : "Copy failed";
        toast.error(msg);
      });
  }, []);

  const handleDownload = React.useCallback(
    (downloadSrc: string | undefined) => {
      setMenu(null);
      if (!downloadSrc) return;
      invokeTauri("download_image", { url: downloadSrc }).catch(
        (err: unknown) => {
          const msg = err instanceof Error ? err.message : "Download failed";
          toast.error(msg);
        },
      );
    },
    [],
  );

  return (
    <>
      <button
        aria-hidden={isHiddenInSpoiler ? true : undefined}
        aria-label={alt?.trim() ? `Zoom image: ${alt}` : "Zoom image"}
        className={cn(
          "mt-1 inline-block min-w-0 max-w-full cursor-zoom-in overflow-hidden rounded-2xl border-0 bg-transparent p-0 text-left align-top focus:outline-hidden focus-visible:ring-2 focus-visible:ring-ring/50",
          lightboxState && "opacity-0",
        )}
        data-image-lightbox-resolved-src={resolvedSrc}
        data-image-lightbox-alt={alt}
        data-image-lightbox-dim={dim}
        data-image-lightbox-src={src}
        data-image-lightbox-trigger=""
        data-testid="message-image-lightbox-trigger"
        ref={triggerRef}
        tabIndex={isHiddenInSpoiler ? -1 : undefined}
        type="button"
        onClick={handleImageTriggerClick}
        onContextMenuCapture={handleContextMenu}
      >
        <ProgressiveImage
          alt={alt}
          fullImageRef={inlineImageRef}
          height={intrinsicDimensions.height}
          onFullLoad={handleImageLoad}
          onThumbnailLoad={updateSpoilerMediaSize}
          resolvedSrc={resolvedSrc}
          showSpoilerSize={Boolean(hiddenSpoilerMediaSize)}
          style={spoilerMediaStyle}
          thumbnailRef={thumbnailImageRef}
          thumbSrc={thumbSrc}
          width={intrinsicDimensions.width}
        />
      </button>
      {menu && src ? (
        <MediaContextMenu
          dataAttributes={["data-image-context-menu"]}
          items={[
            { label: "Copy image", onSelect: () => handleCopyImage(src) },
            { label: "Download image", onSelect: () => handleDownload(src) },
          ]}
          position={menu}
        />
      ) : null}
      {lightboxState && resolvedSrc ? (
        <ImageZoomOverlay
          alt={alt}
          galleryIndex={lightboxState.galleryIndex}
          galleryItems={lightboxState.galleryItems}
          onCopy={handleCopyImage}
          onDownload={handleDownload}
          onClose={() => setLightboxState(null)}
          resolvedSrc={resolvedSrc}
          sourceBox={lightboxState.sourceBox}
          sourceCornerRadii={lightboxState.sourceCornerRadii}
          sourceScope={lightboxState.sourceScope}
          src={src}
        />
      ) : null}
    </>
  );
}

function ImageMosaic({ children }: { children: React.ReactNode[] }) {
  const mosaicRef = React.useRef<HTMLDivElement | null>(null);
  const isTriptych = children.length === 3;
  const hasOddTail = children.length > 3 && children.length % 2 === 1;
  useSmoothCorners(mosaicRef);

  return (
    <div
      className={cn(
        "mt-1 grid w-full min-w-0 max-w-lg grid-cols-2 gap-1.5 overflow-hidden rounded-2xl [&_br]:hidden [&_[data-block-media]]:min-h-0 [&_[data-block-media]]:max-w-none [&_[data-block-media]]:overflow-hidden [&_[data-block-media]>button]:m-0 [&_[data-block-media]>button]:h-full [&_[data-block-media]>button]:w-full [&_[data-block-media]>button]:max-w-none [&_[data-block-media]>button]:rounded-none [&_[data-block-media]_[data-progressive-image-frame]]:!h-full [&_[data-block-media]_[data-progressive-image-frame]]:!w-full [&_[data-block-media]_img]:!h-full [&_[data-block-media]_img]:!max-h-none [&_[data-block-media]_img]:!w-full [&_[data-block-media]_img]:!max-w-none [&_[data-block-media]_img]:rounded-none [&_[data-block-media]_img]:object-cover",
        isTriptych
          ? "h-80 grid-rows-2 [&_[data-block-media]]:h-auto [&_[data-block-media]:first-child]:row-span-2"
          : "[&_[data-block-media]]:h-48",
        hasOddTail && "[&_[data-block-media]:last-child]:col-span-2",
      )}
      data-image-mosaic=""
      data-image-mosaic-count={children.length}
      ref={mosaicRef}
    >
      {children}
    </div>
  );
}

export function createMarkdownComponents(
  interactive = true,
  mediaInset = false,
): Components {
  const listItemClassName = "[&_p]:inline";
  const listClassName = "space-y-1 pl-6 marker:text-muted-foreground/80";

  function MarkdownAnchor({
    children,
    href,
    ...props
  }: React.ComponentPropsWithoutRef<"a">) {
    const {
      channels,
      imetaByUrl,
      onOpenEntityLink,
      resolveChannelReferences,
      onOpenMessageLink,
      onOpenChannel,
      onImportSnapshotFromUrl,
      relayOrigin,
      snapshotSharedBy,
    } = useMarkdownRuntime();
    if (!interactive) {
      return <span className="font-medium text-current">{children}</span>;
    }

    // Markdown image-link syntax (`[![alt](src)](href)`) otherwise nests the
    // image lightbox button inside an anchor. Keep the image as the lightbox
    // trigger and suppress the parent link activation for block media.
    if (hasBlockMedia(React.Children.toArray(children))) {
      return <>{children}</>;
    }

    const label = getReactNodeText(children);
    if (href && parseChannelLink(href).ok) {
      return (
        <ChannelDeepLinkAnchor href={href} interactive={interactive}>
          {children}
        </ChannelDeepLinkAnchor>
      );
    }

    const audioAttachment = renderAudioMessageAttachment(
      href ? imetaByUrl?.get(href) : undefined,
      href,
      label,
      href && isRelayDownloadable(href, relayOrigin ?? undefined)
        ? href
        : undefined,
    );
    if (audioAttachment) return audioAttachment;

    // Snapshot attachment (agent or team): classify before generic FileCard.
    // resolveSnapshotCard checks the filename suffix + SHA-256 field.
    const snapshotCard = resolveSnapshotCard(
      href ? imetaByUrl?.get(href) : undefined,
      href,
      label,
    );
    if (snapshotCard) {
      return (
        <AgentSnapshotCard
          displayName={snapshotCard.displayName}
          href={snapshotCard.href}
          filename={snapshotCard.filename}
          sharedBy={snapshotSharedBy}
          size={snapshotCard.size}
          sha256={snapshotCard.sha256}
          snapshotKind={snapshotCard.snapshotKind}
          thumb={snapshotCard.thumb}
          onImport={(fileBytes, fileName) => {
            onImportSnapshotFromUrl?.(
              fileBytes,
              fileName,
              snapshotCard.snapshotKind,
            );
          }}
        />
      );
    }

    // Generic file attachment: a `[filename](url)` link whose href matches an
    // imeta entry with a non-image, non-video MIME. Render a download card
    // instead of a plain link. (Media uses the `img` renderer, not this path.)
    const card = resolveFileCard(
      href ? imetaByUrl?.get(href) : undefined,
      href,
      label,
    );
    if (card) {
      return (
        <FileCard href={card.href} filename={card.filename} size={card.size} />
      );
    }

    // Intercept `buzz://message?channel=…&id=…` links so a click navigates
    // in-app instead of opening the URL in the OS browser. http(s) links
    // continue to use the existing target="_blank" behavior.
    if (href) {
      const messageLinkTarget = resolveMessageLinkRenderTarget({
        href,
        label,
      });
      if (messageLinkTarget.kind !== "none") {
        if (messageLinkTarget.kind === "pill") {
          return (
            <MessageLinkPill
              channels={channels}
              resolveChannelReference={resolveChannelReferences}
              href={href}
              interactive={interactive}
              link={messageLinkTarget.link}
              onOpenMessageLink={onOpenMessageLink}
              onOpenChannel={onOpenChannel}
            />
          );
        }

        return (
          <AuthoredDeepLinkAnchor
            channelId={messageLinkTarget.link.channelId}
            href={href}
            interactive={interactive}
            messageLink={messageLinkTarget.link}
          >
            {children}
          </AuthoredDeepLinkAnchor>
        );
      }
      // Malformed message deep link — fall through to the default
      // anchor (renders as a normal external link).
    }

    // `buzz://pr|issue|repo?…` entity links navigate in-app; malformed ones
    // fall through to the default anchor.
    if (
      href &&
      (parseEntityLink(href).ok ||
        parseSupportedLinkPreview(href, relayOrigin)?.href.startsWith(
          "buzz://",
        ))
    ) {
      return (
        <EntityLinkAnchor
          asChip={label === href}
          href={href}
          interactive={interactive}
          onOpenEntityLink={onOpenEntityLink}
          relayOrigin={relayOrigin}
        >
          {children}
        </EntityLinkAnchor>
      );
    }

    const supportedLinkPreview = href
      ? parseSupportedLinkPreview(href, relayOrigin)
      : null;
    const isLinearLink = supportedLinkPreview?.kind === "linear-issue";

    return (
      <ExternalLinkAnchor
        anchorProps={props}
        href={href}
        isLinearLink={isLinearLink}
        label={label}
      >
        {children}
      </ExternalLinkAnchor>
    );
  }

  return {
    spoiler: ({
      children,
      ...props
    }: {
      "data-block-spoiler"?: string;
      children?: React.ReactNode;
    }) => (
      <SpoilerInline
        block={props["data-block-spoiler"] != null}
        interactive={interactive}
      >
        {children}
      </SpoilerInline>
    ),
    a: MarkdownAnchor,
    blockquote: ({ children }) => (
      <blockquote className="border-l-2 border-border pl-4 italic text-muted-foreground [&>*:first-child]:mt-0 [&>*+*]:mt-2">
        {children}
      </blockquote>
    ),
    br: () => <br />,
    code: ({ children, className, ...props }: React.ComponentProps<"code">) => {
      const rawCode = String(children);
      const code = rawCode.replace(/\n$/, "");
      const isFencedCodeBlock =
        typeof className === "string" && className.includes("language-");

      if (isFencedCodeBlock || rawCode.endsWith("\n") || code.includes("\n")) {
        const language = extractLanguage(className);

        if (language) {
          return (
            <SyntaxHighlightedCode code={code} language={language} {...props} />
          );
        }

        const lines = code.split("\n");
        return (
          <code {...props} className={CODE_BLOCK_CLASS}>
            {lines.map((line, i) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: lines are positional
              <span key={i} data-line="">
                {line}
              </span>
            ))}
          </code>
        );
      }

      return (
        <code {...props} className={cn(INLINE_CODE_CHIP_CLASS, className)}>
          {children}
        </code>
      );
    },
    h1: ({ children }) => (
      <h1 className="text-xl font-semibold leading-8 tracking-tight">
        {children}
      </h1>
    ),
    h2: ({ children }) => (
      <h2 className="text-lg font-semibold leading-7 tracking-tight">
        {children}
      </h2>
    ),
    h3: ({ children }) => (
      <h3 className="text-base font-semibold leading-6 tracking-tight">
        {children}
      </h3>
    ),
    h4: ({ children }) => (
      <h4 className="text-sm font-semibold leading-5 tracking-tight">
        {children}
      </h4>
    ),
    h5: ({ children }) => (
      <h5 className="text-sm font-semibold leading-5 tracking-tight">
        {children}
      </h5>
    ),
    h6: ({ children }) => (
      <h6 className="text-sm font-medium leading-5 tracking-tight text-muted-foreground">
        {children}
      </h6>
    ),
    hr: () => <hr className="border-border/80" />,
    img: function MarkdownImage({ alt, src }) {
      const { imetaByUrl } = useMarkdownRuntime();
      const entry = src ? imetaByUrl?.get(src) : undefined;
      const isVideo = src ? isVideoMedia(src, entry?.m) : false;
      if (!interactive) {
        const fallbackLabel = isVideo ? "Video attachment" : "Image attachment";
        return <span>{alt?.trim() || fallbackLabel}</span>;
      }

      const resolvedSrc = src ? rewriteRelayUrl(src) : src;
      if (isVideo && src && resolvedSrc) {
        return (
          <span
            className={cn(
              mediaInset && "mx-1.5 block max-w-[calc(100%-0.75rem)]",
            )}
            data-block-media=""
          >
            <MarkdownVideoPlayer
              key={src ?? resolvedSrc}
              alt={alt}
              entry={entry}
              resolvedSrc={resolvedSrc}
              src={src}
            />
          </span>
        );
      }
      return (
        <span data-block-media="" className="block min-w-0 max-w-full">
          <ImageBlock
            alt={alt}
            dim={entry?.dim}
            resolvedSrc={resolvedSrc}
            src={src}
            thumbSrc={entry?.thumb ? rewriteRelayUrl(entry.thumb) : undefined}
          />
        </span>
      );
    },
    input: MarkdownInput,
    li: ({ children }) => <li className={listItemClassName}>{children}</li>,
    ol: ({ children }) => (
      <ol className={cn("list-decimal", listClassName)}>{children}</ol>
    ),
    p: function MarkdownParagraph({ children }) {
      const { imetaByUrl } = useMarkdownRuntime();
      // Detect media-only paragraphs (images + <br> from remarkBreaks).
      // Multi-image: render as a compact, count-aware mosaic. Two images split
      // a row, three form a hero-and-stack triptych, and larger odd counts let
      // the final image span both columns.
      // Single media: render as a plain <div> to avoid invalid <p><div> nesting
      // (the img component returns block-level wrappers for lightbox/video).
      const childArray = React.Children.toArray(children);
      const { imageChildren } = classifyChildren(childArray);

      if (isImageOnlyParagraph(childArray)) {
        return <ImageMosaic>{imageChildren}</ImageMosaic>;
      }

      const hasAudioAttachment = childArray.some(
        (child) =>
          React.isValidElement<{ href?: string }>(child) &&
          typeof child.props.href === "string" &&
          isAudioAttachment(imetaByUrl?.get(child.props.href)),
      );
      if (hasBlockMedia(childArray) || hasAudioAttachment) {
        return <div>{children}</div>;
      }

      return <p>{children}</p>;
    },
    pre: ({ children }) => {
      if (!interactive) return <span>{children}</span>;
      let language = "";
      React.Children.forEach(children, (child) => {
        if (
          React.isValidElement<Record<string, unknown>>(child) &&
          typeof child.props?.className === "string"
        ) {
          language = extractLanguage(child.props.className);
        }
      });
      return (
        <MarkdownCodeBlock language={language}>{children}</MarkdownCodeBlock>
      );
    },
    strong: ({ children }) => (
      <strong className="font-semibold">{children}</strong>
    ),
    table: ({ children }) => <MarkdownTable>{children}</MarkdownTable>,
    td: ({ children }) => (
      <td className="border-t border-border/70 px-3 py-2 align-top">
        {children}
      </td>
    ),
    th: ({ children }) => (
      <th className="bg-muted/60 px-3 py-2 font-semibold text-foreground">
        {children}
      </th>
    ),
    ul: ({ children }) => (
      <ul className={cn("list-disc", listClassName)}>{children}</ul>
    ),
    mention: createMarkdownMention(interactive),
    emoji: ({ src, alt }: { src?: string; alt?: string }) => {
      const resolvedSrc = src ? rewriteRelayUrl(src) : src;
      if (!resolvedSrc) {
        return <span>{alt}</span>;
      }
      if (!interactive) {
        return <span>{alt}</span>;
      }
      return <InlineEmojiPopover alt={alt} resolvedSrc={resolvedSrc} />;
    },
    "channel-link": function ChannelReference(props: {
      children?: React.ReactNode;
    }) {
      return <MarkdownChannelReference {...props} interactive={interactive} />;
    },
    "channel-deep-link": function ChannelDeepLink(props: {
      children?: React.ReactNode;
    }) {
      return <MarkdownChannelDeepLink {...props} interactive={interactive} />;
    },
    "entity-link": function MarkdownEntityLink({
      children,
    }: {
      children?: React.ReactNode;
    }) {
      const { onOpenEntityLink, relayOrigin } = useMarkdownRuntime();
      const href = String(children ?? "");
      if (!parseEntityLink(href).ok) return <span>{children}</span>;
      return (
        <EntityLinkAnchor
          href={href}
          interactive={interactive}
          onOpenEntityLink={onOpenEntityLink}
          relayOrigin={relayOrigin}
        >
          {children}
        </EntityLinkAnchor>
      );
    },
    "message-link": function MarkdownMessageLink({
      children,
    }: {
      children?: React.ReactNode;
    }) {
      const {
        channels,
        onOpenMessageLink,
        onOpenChannel,
        resolveChannelReferences,
      } = useMarkdownRuntime();
      const href = String(children ?? "");
      const parsed = parseMessageLink(href);
      if (!parsed.ok) {
        // Malformed `buzz://message?…` — render the raw URL as plain text
        // rather than a misleading clickable pill.
        return <span data-message-link="">{href}</span>;
      }

      return (
        <MessageLinkPill
          channels={channels}
          resolveChannelReference={resolveChannelReferences}
          href={href}
          interactive={interactive}
          link={parsed.value}
          onOpenMessageLink={onOpenMessageLink}
          onOpenChannel={onOpenChannel}
        />
      );
    },
  } as Components;
}

/**
 * The component map only varies by the two boolean render flags, so at most
 * four instances ever exist. Module-stable maps mean cached markdown element
 * trees (see ./markdown/nodeCache.ts) never embed per-mount closures.
 */
const MARKDOWN_COMPONENT_SCHEMA_VERSION = "6";
const markdownComponentsByVariant = new Map<string, MarkdownComponentSet>();

type MarkdownComponentSet = { components: Components; variant: string };

/**
 * Returns the component map together with the `variant` token that fully
 * identifies it. The token doubles as the variant segment of the parse-cache
 * key (see nodeCache.ts), so the map partitioning and the key partitioning
 * come from one place and cannot drift apart: a new render flag added here
 * automatically partitions the cache too.
 */
function getMarkdownComponents(
  interactive: boolean,
  mediaInset: boolean,
): MarkdownComponentSet {
  const variant = `${MARKDOWN_COMPONENT_SCHEMA_VERSION}:${interactive ? "i" : ""}${mediaInset ? "m" : ""}`;
  let entry = markdownComponentsByVariant.get(variant);
  if (!entry) {
    entry = {
      components: createMarkdownComponents(interactive, mediaInset),
      variant,
    };
    markdownComponentsByVariant.set(variant, entry);
  }
  return entry;
}

function MarkdownInner({
  channelNames,
  className,
  configNudgeAuthorPubkey,
  content,
  customEmoji,
  imetaByUrl,
  interactive = true,
  agentMentionPubkeysByName,
  mediaInset = false,
  messageId,
  linkPreviewsSuppressed = false,
  linkPreviewTags,
  onRemoveLinkPreviewsForEveryone,
  mentionNames,
  mentionPubkeysByName,
  leadingInlineContent,
  searchQuery,
  snapshotSharedBy,
  videoReviewContext,
}: MarkdownProps) {
  const { channels: rawChannels } = useChannelNavigation();
  const channels = useStableArray(rawChannels);
  const { goChannel, goAgents } = useAppNavigation();
  const onOpenChannel = React.useCallback(
    (channelId: string) => {
      void goChannel(channelId);
    },
    [goChannel],
  );
  const onOpenEntityLink = useOpenEntityLink();
  const onOpenMessageLink = React.useCallback(
    (link: ParsedMessageLink) => {
      // Always route through `goChannel` with `messageId` set: the channel
      // route already handles scroll-into-view + highlight via
      // `useAnchoredScroll` + `getEventById` backfill, and works for
      // both stream-message replies and forum threads. Detecting "the thread
      // root is a forum post" up front would require an event lookup we don't
      // currently have synchronously; the brief explicitly allows skipping
      // that detection and falling through.
      void goChannel(link.channelId, {
        messageId: link.messageId,
        threadRootId: link.threadRootId,
      });
    },
    [goChannel],
  );
  const relayOrigin = useRelayOrigin();
  const resolvedLinkPreviews = React.useMemo(
    () =>
      interactive && !linkPreviewsSuppressed
        ? parseLinkPreviewSnapshots(linkPreviewTags, content, relayOrigin)
        : [],
    [
      content,
      interactive,
      linkPreviewTags,
      linkPreviewsSuppressed,
      relayOrigin,
    ],
  );
  const configNudge = React.useMemo(
    () => computeConfigNudge(content, interactive, configNudgeAuthorPubkey),
    [content, interactive, configNudgeAuthorPubkey],
  );
  const runtime = React.useMemo<MarkdownRuntime>(
    () => ({
      agentMentionPubkeysByName,
      resolveChannelReferences: true,
      channels,
      imetaByUrl,
      mentionPubkeysByName,
      onOpenChannel,
      onOpenEntityLink,
      onOpenMessageLink,
      relayOrigin,
      snapshotSharedBy,
      onImportSnapshotFromUrl: (
        fileBytes: number[],
        fileName: string,
        snapshotKind: "agent" | "team",
      ) => {
        requestOpenSnapshotImport({ fileBytes, fileName, snapshotKind });
        void goAgents();
      },
    }),
    [
      agentMentionPubkeysByName,
      channels,
      imetaByUrl,
      mentionPubkeysByName,
      onOpenChannel,
      onOpenEntityLink,
      onOpenMessageLink,
      relayOrigin,
      snapshotSharedBy,
      goAgents,
    ],
  );

  let processedContent = content;

  // Note: stripping the sentinel here is intentionally omitted. When
  // configNudge !== null, selectProseOrNudge() returns null — suppressing
  // the prose node entirely — so processedContent is never rendered and
  // stripConfigNudgeSentinel would be dead work on that path.

  if (/^(?:\s{2}\n)+/.test(processedContent)) {
    processedContent = `\u200B${processedContent}`;
  }

  if (/(?:\s{2}\n)+$/.test(processedContent)) {
    processedContent = `${processedContent}\u200B`;
  }

  const entityCardOpenHandlers = useEntityCardOpenHandlers(
    resolvedLinkPreviews,
    onOpenEntityLink,
  );

  // When a config-nudge suppresses the prose (selectProseOrNudge returns
  // null), skip the parse entirely — it would be thrown away unrendered.
  const componentSet = getMarkdownComponents(interactive, mediaInset);
  const markdownNode =
    configNudge === null
      ? renderCachedMarkdown({
          channelNames,
          components: componentSet.components,
          content: processedContent,
          customEmoji,
          mentionNames,
          searchQuery,
          variant: componentSet.variant,
        })
      : null;

  return (
    <div
      className={cn(
        MESSAGE_MARKDOWN_CLASS,
        [
          "max-w-none wrap-anywhere text-sm leading-5 text-foreground",
          "[&>*:first-child]:mt-0 [&>*:last-child]:mb-0",
          "[&>*+*]:mt-3",
          "[&>p+p]:mt-1.5",
          "[&>*+h1]:mt-3.5 [&>*+h2]:mt-3.5 [&>*+h3]:mt-3.5 [&>*+h4]:mt-3.5 [&>*+h5]:mt-3.5 [&>*+h6]:mt-3.5",
          "[&>h1+*]:mt-0.5 [&>h2+*]:mt-0.5 [&>h3+*]:mt-0.5 [&>h4+*]:mt-0.5 [&>h5+*]:mt-0.5 [&>h6+*]:mt-0.5",
          "[&>h1+h2]:mt-1.5! [&>h2+h3]:mt-1.5! [&>h3+h4]:mt-1.5! [&>h4+h5]:mt-1.5! [&>h5+h6]:mt-1.5!",
          "[&>*+blockquote]:mt-3.5 [&>blockquote+*]:mt-3.5",
          "[&>*+[data-code-block]]:mt-3.5 [&>[data-code-block]+*]:mt-3.5",
          "[&>*+[data-table-block]]:mt-3.5 [&>[data-table-block]+*]:mt-3.5",
          "[&>*+hr]:mt-4 [&>hr+*]:mt-4",
          "[&>p+ul]:mt-1.5 [&>p+ol]:mt-1.5 [&>div+ul]:mt-1.5 [&>div+ol]:mt-1.5",
        ].join(" "),
        className,
      )}
    >
      <MarkdownRuntimeContext.Provider value={runtime}>
        <VideoReviewMarkdownContext.Provider value={videoReviewContext}>
          {leadingInlineContent}
          {selectProseOrNudge(configNudge, markdownNode)}
          {configNudge !== null ? (
            <AttachmentGroup
              className="max-w-full flex-wrap overflow-visible pb-0"
              data-config-nudge=""
            >
              <ConfigNudgeCard nudge={configNudge} />
            </AttachmentGroup>
          ) : null}
          <LinkPreviewList
            ImageLightbox={LinkPreviewImageLightbox}
            key={messageId}
            onOpenByHref={entityCardOpenHandlers}
            onRemoveForEveryone={onRemoveLinkPreviewsForEveryone}
            previews={resolvedLinkPreviews}
          />
        </VideoReviewMarkdownContext.Provider>
      </MarkdownRuntimeContext.Provider>
    </div>
  );
}

export const Markdown = React.memo(
  MarkdownInner,
  (prev, next) =>
    prev.content === next.content &&
    prev.className === next.className &&
    prev.customEmoji === next.customEmoji &&
    prev.interactive === next.interactive &&
    prev.mediaInset === next.mediaInset &&
    shallowRecordEqual(
      prev.agentMentionPubkeysByName,
      next.agentMentionPubkeysByName,
    ) &&
    shallowRecordEqual(prev.mentionPubkeysByName, next.mentionPubkeysByName) &&
    shallowArrayEqual(prev.mentionNames, next.mentionNames) &&
    prev.leadingInlineContent === next.leadingInlineContent &&
    shallowArrayEqual(prev.channelNames, next.channelNames) &&
    prev.imetaByUrl === next.imetaByUrl &&
    prev.configNudgeAuthorPubkey === next.configNudgeAuthorPubkey &&
    prev.searchQuery === next.searchQuery &&
    prev.snapshotSharedBy === next.snapshotSharedBy &&
    prev.videoReviewContext === next.videoReviewContext,
);
Markdown.displayName = "Markdown";
export { SyntaxHighlightedCode } from "./markdown/CodeBlock";
