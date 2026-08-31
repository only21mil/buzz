import * as React from "react";
import { useMediaUpload } from "@/features/messages/lib/useMediaUpload";
import type { MessageComposerProps } from "./MessageComposer.types";

export type ImplProps = Omit<MessageComposerProps, "mediaController"> & {
  mediaController: NonNullable<MessageComposerProps["mediaController"]>;
  ownsMediaController: boolean;
};

type MessageComposerImplementation = React.ComponentType<ImplProps>;

export function withOwnedMedia(
  MessageComposerImpl: MessageComposerImplementation,
) {
  function MessageComposerWithOwnedMedia(props: MessageComposerProps) {
    const mediaController = useMediaUpload({ deferUploadsUntilSend: true });
    return (
      <MessageComposerImpl
        {...props}
        mediaController={mediaController}
        ownsMediaController
      />
    );
  }

  function MessageComposerRoot(props: MessageComposerProps) {
    if (props.mediaController) {
      return (
        <MessageComposerImpl
          {...props}
          mediaController={props.mediaController}
          ownsMediaController={false}
        />
      );
    }

    return <MessageComposerWithOwnedMedia {...props} />;
  }

  return React.memo(MessageComposerRoot);
}
