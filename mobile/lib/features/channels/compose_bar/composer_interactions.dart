part of '../compose_bar.dart';

Widget _buildComposeBarContextMenu(
  BuildContext context,
  WidgetRef ref,
  EditableTextState editableTextState, {
  required ValueNotifier<bool> clipboardHasImage,
  required ValueNotifier<String?> uploadError,
  required void Function(XFile file, _PendingAttachmentKind kind)
  queueAttachment,
}) {
  void pasteImage() {
    ContextMenuController.removeAny();
    unawaited(() async {
      try {
        final image = await ref
            .read(mediaUploadServiceProvider)
            .readClipboardImage();
        if (image != null && context.mounted) {
          queueAttachment(image, _PendingAttachmentKind.image);
        } else if (context.mounted) {
          uploadError.value = 'Unable to read pasted image';
        }
      } catch (error) {
        if (context.mounted) uploadError.value = _formatUploadError(error);
      }
    }());
  }

  if (defaultTargetPlatform == TargetPlatform.iOS &&
      SystemContextMenu.isSupportedByField(editableTextState)) {
    return SystemContextMenu.editableText(
      editableTextState: editableTextState,
      items: [
        if (clipboardHasImage.value)
          IOSSystemContextMenuItemCustom(
            title: 'Paste Image',
            onPressed: pasteImage,
          ),
        ...SystemContextMenu.getDefaultItems(editableTextState),
      ],
    );
  }

  final buttonItems = [...editableTextState.contextMenuButtonItems];
  if (defaultTargetPlatform == TargetPlatform.iOS && clipboardHasImage.value) {
    buttonItems.insert(
      0,
      ContextMenuButtonItem(label: 'Paste Image', onPressed: pasteImage),
    );
  }
  return AdaptiveTextSelectionToolbar.buttonItems(
    anchors: editableTextState.contextMenuAnchors,
    buttonItems: buttonItems,
  );
}

void _uploadComposeBarPastedImage(
  KeyboardInsertedContent content, {
  required ValueNotifier<String?> uploadError,
  required void Function(XFile file, _PendingAttachmentKind kind)
  queueAttachment,
}) {
  final bytes = content.data;
  if (bytes == null || bytes.isEmpty) {
    uploadError.value = 'Unable to read pasted image';
    return;
  }

  queueAttachment(
    XFile.fromData(bytes, name: 'Pasted image'),
    _PendingAttachmentKind.image,
  );
}

void _applyComposeBarFormat(
  _MarkdownEditingController controller,
  FocusNode focusNode,
  ObjectRef<bool> isModifyingText,
  String prefix, [
  String? suffix,
]) {
  suffix ??= prefix;
  final text = controller.text;
  final sel = controller.selection;
  if (!sel.isValid) return;

  isModifyingText.value = true;
  try {
    if (sel.isCollapsed) {
      final offset = sel.baseOffset;
      final updated =
          '${text.substring(0, offset)}$prefix$suffix${text.substring(offset)}';
      controller.text = updated;
      controller.selection = TextSelection.collapsed(
        offset: offset + prefix.length,
      );
    } else {
      final selected = text.substring(sel.start, sel.end);
      final updated =
          '${text.substring(0, sel.start)}$prefix$selected$suffix${text.substring(sel.end)}';
      controller.text = updated;
      controller.selection = TextSelection.collapsed(
        offset: sel.start + prefix.length + selected.length + suffix.length,
      );
    }
  } finally {
    isModifyingText.value = false;
  }
  focusNode.requestFocus();
}

Future<void> _handleComposeBarAttachmentTap({
  required BuildContext context,
  required BuildContext triggerContext,
  required WidgetRef ref,
  required FocusNode focusNode,
  required ValueNotifier<_AttachmentSurface> attachmentSurface,
  required _IOSAttachmentPopoverController iosAttachmentPopover,
  required _ComposerVoiceNote voiceNote,
  required Future<void> Function(List<XFile> images) retainAndQueueImages,
  required bool Function(List<XFile> images, {bool deleteAfterUse}) queueImages,
  required Future<void> Function({
    required Future<XFile?> Function() pick,
    required _PendingAttachmentKind kind,
  })
  pickThenQueue,
  required void Function(Future<void> Function() choose, {String? errorMessage})
  chooseAttachment,
  required VoidCallback toggleAttachments,
}) async {
  if (defaultTargetPlatform != TargetPlatform.iOS ||
      attachmentSurface.value != _AttachmentSurface.closed) {
    toggleAttachments();
    return;
  }

  final didPresent = await iosAttachmentPopover.present(
    sourceContext: triggerContext,
    onCapture: (image) => retainAndQueueImages([image]),
    onChoosePhotos: retainAndQueueImages,
    onAllPhotos: () => chooseAttachment(() async {
      final photos = await ref
          .read(mediaUploadServiceProvider)
          .pickGalleryImages();
      queueImages(photos);
    }, errorMessage: 'Unable to open your photo library.'),
    onVideo: () => chooseAttachment(() {
      final service = ref.read(mediaUploadServiceProvider);
      return pickThenQueue(
        pick: service.pickGalleryVideo,
        kind: _PendingAttachmentKind.video,
      );
    }),
    onVoiceNote: voiceNote.start,
    onFiles: () => chooseAttachment(() {
      final service = ref.read(mediaUploadServiceProvider);
      return pickThenQueue(
        pick: service.pickAttachmentFile,
        kind: _PendingAttachmentKind.file,
      );
    }),
  );
  if (!didPresent && context.mounted) {
    focusNode.unfocus();
    toggleAttachments();
  }
}

Widget _buildComposeBarOverlayPanel({
  required _AttachmentSurface surface,
  required Widget suggestionPanel,
  required ValueNotifier<_AttachmentSurface> attachmentSurface,
  required FocusNode focusNode,
  required _ComposerVoiceNote voiceNote,
  required WidgetRef ref,
  required Future<void> Function(List<XFile> images) retainAndQueueImages,
  required bool Function(List<XFile> images, {bool deleteAfterUse}) queueImages,
  required Future<void> Function({
    required Future<XFile?> Function() pick,
    required _PendingAttachmentKind kind,
  })
  pickThenQueue,
  required void Function(Future<void> Function() choose, {String? errorMessage})
  chooseAttachment,
}) {
  return _AttachmentSurfacePanel(
    key: ValueKey(
      surface == _AttachmentSurface.closed
          ? 'composer-suggestions'
          : 'attachment-surface',
    ),
    surface: surface,
    suggestionPanel: suggestionPanel,
    onBack: () => attachmentSurface.value = _AttachmentSurface.menu,
    onCamera: () {
      focusNode.unfocus();
      attachmentSurface.value = _AttachmentSurface.camera;
    },
    onPhotos: () {
      focusNode.unfocus();
      attachmentSurface.value = _AttachmentSurface.photos;
    },
    onVideo: () => chooseAttachment(() {
      final service = ref.read(mediaUploadServiceProvider);
      return pickThenQueue(
        pick: service.pickGalleryVideo,
        kind: _PendingAttachmentKind.video,
      );
    }),
    onVoiceNote: voiceNote.start,
    onFiles: () => chooseAttachment(() {
      final service = ref.read(mediaUploadServiceProvider);
      return pickThenQueue(
        pick: service.pickAttachmentFile,
        kind: _PendingAttachmentKind.file,
      );
    }),
    onCapture: (image) async {
      attachmentSurface.value = _AttachmentSurface.closed;
      await retainAndQueueImages([image]);
    },
    onPickAllPhotos: ref.read(mediaUploadServiceProvider).pickGalleryImages,
    onChoosePhotos: (photos) async {
      attachmentSurface.value = _AttachmentSurface.closed;
      await retainAndQueueImages(photos);
    },
    onChooseAllPhotos: (photos) async {
      attachmentSurface.value = _AttachmentSurface.closed;
      queueImages(photos);
    },
  );
}
