part of '../compose_bar.dart';

/// Rich compose bar with @mention autocomplete and a markdown formatting
/// toolbar. Used in both channel and thread views — the caller provides an
/// [onSend] callback that handles actual message submission.
typedef ComposeBarOnSend =
    Future<void> Function(
      String content,
      List<String> mentionPubkeys, {
      List<List<String>> mediaTags,
    });

class ComposeBar extends HookConsumerWidget {
  final String channelId;
  final String channelName;
  final String? hintText;
  final ComposeBarOnSend onSend;

  /// Optional thread IDs for thread-scoped typing indicators.
  final String? threadHeadId;
  final String? rootId;
  const ComposeBar({
    super.key,
    required this.channelId,
    this.channelName = '',
    this.hintText,
    this.threadHeadId,
    this.rootId,
    required this.onSend,
  });
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final controller = useMemoized(_MarkdownEditingController.new);
    useListenable(controller);
    useEffect(() => controller.dispose, [controller]);
    // Restore and persist unsent text as a local draft so the Activity
    // inbox Drafts filter reflects real composer state.
    //
    // The effect is additionally keyed on the active relay + pubkey identity:
    // provider-level namespacing alone cannot protect a composer that stays
    // mounted through an in-place community/account switch — the controller
    // would retain the old identity's text and the next edit would persist it
    // into the new identity's store. On identity change we replace the
    // controller content with the new identity's own saved draft (or clear).
    final draftKey = composeDraftKey(channelId, threadHeadId: threadHeadId);
    final draftRevision = useRef(0);
    final draftIdentity =
        '${ref.watch(relayConfigProvider).baseUrl}'
        ':${ref.watch(myPubkeyProvider) ?? 'anon'}';
    final focusNode = useFocusNode();
    useEffect(
      () =>
          () => _dismissComposerKeyboard(focusNode),
      [focusNode],
    );
    final isComposerExpanded = useState(false);
    final isEmojiPickerOpen = useState(false);
    final attachmentSurface = useState(_AttachmentSurface.closed);
    final iosAttachmentPopover = useMemoized(
      _IOSAttachmentPopoverController.new,
    );
    useEffect(
      () =>
          () => unawaited(iosAttachmentPopover.dispose()),
      [iosAttachmentPopover],
    );
    final isSending = useState(false);
    final showFormatting = useState(false);
    final attachments = useState<List<_PendingAttachment>>([]);
    _useOwnedAttachmentCleanup(attachments);
    final uploadError = useState<String?>(null);
    final uploadingCount = useState(0);
    final uploadProgress = useState(0.0);
    final uploadGeneration = useRef(0);
    final activeUploadCancellation = useRef<UploadCancellationToken?>(null);
    final voiceNote = _useComposerVoiceNote(
      context: context,
      ref: ref,
      focusNode: focusNode,
      isComposerExpanded: isComposerExpanded,
      showFormatting: showFormatting,
      attachmentSurface: attachmentSurface,
      uploadError: uploadError,
      draftRevision: draftRevision,
      attachments: attachments,
    );
    final voiceNoteRef = useRef(voiceNote)..value = voiceNote;
    // Map of displayName → selected mention candidate built as the user selects
    // mentions. Declared before the draft lifecycle so restored drafts can
    // hydrate it, and so every send resolves against the same bindings.
    final mentionMap = useRef(<String, MentionCandidate>{});
    _useComposeDraftLifecycle(
      mentionMap: mentionMap,
      ref: ref,
      controller: controller,
      draftKey: draftKey,
      channelId: channelId,
      threadHeadId: threadHeadId,
      draftIdentity: draftIdentity,
      draftRevision: draftRevision,
      attachments: attachments,
      uploadGeneration: uploadGeneration,
      activeUploadCancellation: activeUploadCancellation,
      uploadingCount: uploadingCount,
      isSending: isSending,
      attachmentSurface: attachmentSurface,
      uploadError: uploadError,
      iosAttachmentPopover: iosAttachmentPopover,
      onDraftIdentityChanged: voiceNote.onDraftIdentityChanged,
    );
    final clipboardHasImage = useState(false);
    final hasAttachments = attachments.value.isNotEmpty;
    final customEmoji = ref.watch(customEmojiListProvider);
    final reducedMotion = MediaQuery.disableAnimationsOf(context);
    final composerExpansionController = useAnimationController(
      initialValue: 0,
      upperBound: 1.05,
    );
    final composerExpansionValue = useAnimation(composerExpansionController);
    final composerExpansionProgress = composerExpansionValue
        .clamp(0.0, 1.0)
        .toDouble();

    void collapseComposer() {
      if (!isComposerExpanded.value) return;
      showFormatting.value = false;
      isComposerExpanded.value = false;
    }

    useEffect(() {
      void collapseWhenUnfocused() {
        if (!focusNode.hasFocus && !isEmojiPickerOpen.value) {
          collapseComposer();
        }
      }

      focusNode.addListener(collapseWhenUnfocused);
      return () => focusNode.removeListener(collapseWhenUnfocused);
    }, [focusNode]);

    final appView = View.of(context);
    useEffect(() {
      final observer = _ComposerKeyboardMetricsObserver(
        view: appView,
        onKeyboardHidden: () {
          voiceNote.onKeyboardHidden();
          collapseComposer();
          focusNode.unfocus();
        },
      );
      WidgetsBinding.instance.addObserver(observer);
      return () => WidgetsBinding.instance.removeObserver(observer);
    }, [appView, focusNode, voiceNote.isPreparing]);
    final resolvedHint =
        hintText ??
        (channelName.isNotEmpty ? 'Message #$channelName' : 'Message\u2026');
    useEffect(() {
      final target = isComposerExpanded.value ? 1.0 : 0.0;
      if (reducedMotion) {
        composerExpansionController.value = target;
      } else if ((composerExpansionController.value - target).abs() > 0.001) {
        composerExpansionController.animateWith(
          SpringSimulation(
            SpringDescription.withDurationAndBounce(
              duration: const Duration(milliseconds: 220),
              bounce: 0.08,
            ),
            composerExpansionController.value,
            target,
            0,
            snapToEnd: true,
          ),
        );
      }
      return null;
    }, [isComposerExpanded.value, reducedMotion]);
    useEffect(() {
      if (defaultTargetPlatform != TargetPlatform.iOS) return null;

      var disposed = false;
      Future<void> refreshClipboardAvailability() async {
        final hasImage = await ref
            .read(mediaUploadServiceProvider)
            .clipboardHasImage();
        if (!disposed && context.mounted) {
          clipboardHasImage.value = hasImage;
        }
      }

      void refreshWhenFocused() {
        if (focusNode.hasFocus) refreshClipboardAvailability();
      }

      final lifecycleListener = AppLifecycleListener(
        onResume: refreshClipboardAvailability,
      );
      focusNode.addListener(refreshWhenFocused);
      refreshClipboardAvailability();
      return () {
        disposed = true;
        focusNode.removeListener(refreshWhenFocused);
        lifecycleListener.dispose();
      };
    }, [focusNode]);

    // Mention state --------------------------------------------------------
    final mentionQuery = useState<String?>(null);
    final mentionStartIdx = useState(-1);

    // Channel autocomplete state ----------------------------------------------
    final channelQuery = useState<String?>(null);
    final channelStartIdx = useState(-1);
    final channelsAsync = ref.watch(channelsProvider);

    final membersAsync = ref.watch(channelMembersProvider(channelId));
    final currentPubkey = ref.watch(currentPubkeyProvider);
    final userCache = ref.watch(userCacheProvider);
    final isDmChannel =
        channelsAsync.asData?.value.any((c) => c.id == channelId && c.isDm) ??
        false;

    // Preload profiles for channel members, mentionable agents, and their
    // owners so @mention suggestions show names ("managed by …" included).
    final relayAgents = ref.watch(agentDirectoryProvider).asData?.value;
    final agentOwners = ref.watch(agentOwnersProvider).asData?.value;
    final agentMentionLabels = _agentMentionLabels(bindings: mentionMap.value);
    final agentMentionLabelsKey = (agentMentionLabels.toList()..sort()).join(
      '\u0000',
    );
    useEffect(() {
      controller.setAgentMentionNames(agentMentionLabels);
      return null;
    }, [controller, agentMentionLabelsKey]);
    useEffect(
      () {
        final memberList = membersAsync.asData?.value ?? <ChannelMember>[];
        final pubkeys = [
          ...memberList.map((m) => m.pubkey),
          // Restored draft identities need profile preloads too, so the
          // mention picker can revalidate them against current state.
          ...mentionMap.value.values
              .where((c) => c.requiresRevalidation && c.pubkey.isNotEmpty)
              .map((c) => c.pubkey),
          ...?relayAgents?.map((a) => a.pubkey),
          ...?agentOwners?.values,
        ];
        if (pubkeys.isNotEmpty) {
          ref.read(userCacheProvider.notifier).preload(pubkeys);
        }
        return null;
      },
      [
        draftIdentity,
        draftKey,
        membersAsync.asData?.value.length,
        relayAgents?.length,
        agentOwners?.length,
      ],
    );

    // Typing indicator broadcast — throttled to one event per 3 seconds.
    final lastTypingSentMs = useRef(0);
    final isModifyingText = useRef(false);

    // Detect @mention query and broadcast typing on text / selection change.
    useEffect(() {
      void listener() {
        if (isModifyingText.value) return;
        final text = controller.text;
        final sel = controller.selection;

        // Broadcast typing indicator (throttled).
        if (text.isNotEmpty) {
          final now = DateTime.now().millisecondsSinceEpoch;
          if (now - lastTypingSentMs.value > _typingThrottleMs) {
            lastTypingSentMs.value = now;
            _sendTypingIndicator(
              ref,
              channelId: channelId,
              threadHeadId: threadHeadId,
              rootId: rootId,
            );
          }
        }

        if (!sel.isValid || !sel.isCollapsed) {
          mentionQuery.value = null;
          channelQuery.value = null;
          return;
        }
        final cursor = sel.baseOffset;
        if (cursor < 1) {
          mentionQuery.value = null;
          channelQuery.value = null;
          return;
        }

        // Walk backward from cursor looking for trigger characters.
        // stopAtSpace: false — @mentions support multi-word display names.
        final atPos = findTrigger(text, cursor, '@', stopAtSpace: false);

        if (atPos != null) {
          mentionQuery.value = text.substring(atPos + 1, cursor).toLowerCase();
          mentionStartIdx.value = atPos;
          channelQuery.value = null;
        } else {
          mentionQuery.value = null;
        }

        // Channel autocomplete detection — only when no @mention is active.
        if (mentionQuery.value == null) {
          final hashPos = findTrigger(text, cursor, '#');
          if (hashPos != null) {
            channelQuery.value = text
                .substring(hashPos + 1, cursor)
                .toLowerCase();
            channelStartIdx.value = hashPos;
          } else {
            channelQuery.value = null;
          }
        } else {
          channelQuery.value = null;
        }
      }

      controller.addListener(listener);
      return () => controller.removeListener(listener);
    }, [controller]);

    // Ranked mention candidates (desktop-parity ordering + eligibility).
    final suggestions = mentionQuery.value == null
        ? const <MentionCandidate>[]
        : ref
              .watch(
                mentionCandidatesProvider((
                  channelId: channelId,
                  query: mentionQuery.value!,
                )),
              )
              .take(_mentionSuggestionLimit)
              .toList();

    // Resolve owner names for the visible "managed by …" subtitles.
    useEffect(() {
      final ownerPubkeys = [for (final s in suggestions) ?s.ownerPubkey];
      if (ownerPubkeys.isNotEmpty) {
        ref.read(userCacheProvider.notifier).preload(ownerPubkeys);
      }
      return null;
    }, [suggestions.length, mentionQuery.value]);

    // Filter channels against the query.
    final channels = channelsAsync.asData?.value ?? <Channel>[];
    final channelSuggestions = filterChannels(channels, channelQuery.value);

    // Insert a selected mention into the text field.
    void insertMention(MentionCandidate candidate) {
      // Same-name picks keep their own recipient: the second Scout gets a
      // qualified label instead of overwriting the first selection.
      final name = selectedMentionLabel(candidate.label, candidate.pubkey, {
        for (final entry in mentionMap.value.entries)
          entry.key: entry.value.pubkey,
      });
      // Track the resolved candidate so we can pass its pubkey and prepare
      // selected non-member agents at send time.
      mentionMap.value[name] = candidate;

      final start = mentionStartIdx.value.clamp(0, controller.text.length);
      spliceAndMoveCursor(
        controller,
        focusNode,
        start: start,
        replacement: '@$name ',
      );
      mentionQuery.value = null;
    }

    // Insert a selected channel into the text field.
    void insertChannel(Channel channel) {
      final start = channelStartIdx.value.clamp(0, controller.text.length);
      spliceAndMoveCursor(
        controller,
        focusNode,
        start: start,
        replacement: '#${channel.name} ',
      );
      channelQuery.value = null;
    }

    // Insert `@` at the cursor to manually trigger mention mode.
    void triggerMention() => _insertTriggerAtCursor(controller, focusNode, '@');

    // Insert `#` at the cursor to manually trigger channel mode.
    void triggerChannel() => _insertTriggerAtCursor(controller, focusNode, '#');

    // Insert a selected emoji at the cursor without replacing the draft.
    void insertEmoji(String emoji) {
      final text = controller.text;
      final selection = controller.selection;
      final cursor = selection.isValid
          ? selection.baseOffset.clamp(0, text.length)
          : text.length;
      controller.value = TextEditingValue(
        text: text.replaceRange(cursor, cursor, emoji),
        selection: TextSelection.collapsed(offset: cursor + emoji.length),
      );
      focusNode.requestFocus();
    }

    void clearComposer() => _clearComposeBar(
      draftRevision: draftRevision,
      controller: controller,
      attachments: attachments,
      mentionMap: mentionMap,
      mentionQuery: mentionQuery,
      channelQuery: channelQuery,
      attachmentSurface: attachmentSurface,
      showFormatting: showFormatting,
      uploadError: uploadError,
      focusNode: focusNode,
    );

    void removeAttachment(int id) {
      _removePendingAttachment(attachments, draftRevision, id);
    }

    Future<void> send() => _sendComposeBarMessage(
      context: context,
      ref: ref,
      channelId: channelId,
      onSend: onSend,
      controller: controller,
      attachments: attachments,
      mentionMap: mentionMap,
      isSending: isSending,
      uploadingCount: uploadingCount,
      uploadProgress: uploadProgress,
      uploadGeneration: uploadGeneration,
      activeUploadCancellation: activeUploadCancellation,
      draftRevision: draftRevision,
      uploadError: uploadError,
      focusNode: focusNode,
      hasAttachments: hasAttachments,
      membersAsync: membersAsync,
      relayAgents: relayAgents,
      agentOwners: agentOwners,
      channels: channels,
      userCache: userCache,
      currentPubkey: currentPubkey,
      customEmoji: customEmoji,
      clearComposer: clearComposer,
    );

    final queueAttachment = useCallback(
      (
        XFile file,
        _PendingAttachmentKind kind, {
        bool deleteAfterUse = false,
      }) => _queueComposerAttachment(
        file,
        kind,
        voiceNoteRef,
        attachments,
        uploadError,
        draftRevision,
        deleteAfterUse: deleteAfterUse,
      ),
      [voiceNoteRef, draftRevision, uploadError, attachments],
    );
    Future<void> pickThenQueue({
      required Future<XFile?> Function() pick,
      required _PendingAttachmentKind kind,
    }) async {
      uploadError.value = null;
      try {
        final picked = await pick();
        if (picked == null || !context.mounted) return;
        queueAttachment(picked, kind);
      } catch (error) {
        if (context.mounted) {
          uploadError.value = _formatUploadError(error);
        }
      }
    }

    bool queueImages(List<XFile> images, {bool deleteAfterUse = false}) =>
        _queueComposerImages(
          images,
          voiceNote,
          attachments,
          uploadError,
          draftRevision,
          deleteAfterUse,
        );

    Future<void> retainAndQueueImages(List<XFile> images) =>
        _retainAndQueueImages(context, images, queueImages);

    Widget buildContextMenu(
      BuildContext context,
      EditableTextState editableTextState,
    ) => _buildComposeBarContextMenu(
      context,
      ref,
      editableTextState,
      clipboardHasImage: clipboardHasImage,
      uploadError: uploadError,
      queueAttachment: queueAttachment,
    );

    void uploadPastedImage(KeyboardInsertedContent content) =>
        _uploadComposeBarPastedImage(
          content,
          uploadError: uploadError,
          queueAttachment: queueAttachment,
        );

    void applyFormat(String prefix, [String? suffix]) => _applyComposeBarFormat(
      controller,
      focusNode,
      isModifyingText,
      prefix,
      suffix,
    );

    void chooseAttachment(
      Future<void> Function() choose, {
      String? errorMessage,
    }) => _rejectsNonVoiceAttachment(voiceNote, attachments.value, uploadError)
        ? attachmentSurface.value = _AttachmentSurface.closed
        : _chooseComposerAttachment(
            context,
            attachmentSurface,
            uploadError,
            choose,
            errorMessage: errorMessage,
          );

    void toggleAttachments() {
      attachmentSurface.value = switch (attachmentSurface.value) {
        _AttachmentSurface.closed => _AttachmentSurface.menu,
        _AttachmentSurface.menu => _AttachmentSurface.closed,
        _AttachmentSurface.camera ||
        _AttachmentSurface.photos => _AttachmentSurface.menu,
      };
    }

    void handleAttachmentTap(BuildContext triggerContext) {
      unawaited(
        _handleComposeBarAttachmentTap(
          context: context,
          triggerContext: triggerContext,
          ref: ref,
          focusNode: focusNode,
          attachmentSurface: attachmentSurface,
          iosAttachmentPopover: iosAttachmentPopover,
          voiceNote: voiceNote,
          retainAndQueueImages: retainAndQueueImages,
          queueImages: queueImages,
          pickThenQueue: pickThenQueue,
          chooseAttachment: chooseAttachment,
          toggleAttachments: toggleAttachments,
        ),
      );
    }

    final motionDuration = reducedMotion
        ? Duration.zero
        : Duration(
            milliseconds:
                attachmentSurface.value == _AttachmentSurface.camera ||
                    attachmentSurface.value == _AttachmentSurface.photos
                ? 320
                : 250,
          );
    final suggestionOverlayController = useMemoized(
      OverlayPortalController.new,
    );

    useEffect(() {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (context.mounted) suggestionOverlayController.show();
      });
      return null;
    }, [suggestionOverlayController]);

    void expandComposer() {
      if (isComposerExpanded.value) return;
      attachmentSurface.value = _AttachmentSurface.closed;
      isComposerExpanded.value = true;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (context.mounted) focusNode.requestFocus();
      });
    }

    final suggestionPanel = channelSuggestions.isNotEmpty
        ? KeyedSubtree(
            key: const ValueKey('channel-suggestions'),
            child: _ChannelSuggestions(
              suggestions: channelSuggestions,
              onSelect: insertChannel,
            ),
          )
        : suggestions.isNotEmpty
        ? KeyedSubtree(
            key: const ValueKey('mention-suggestions'),
            child: _MentionSuggestions(
              suggestions: suggestions,
              userCache: userCache,
              currentPubkey: currentPubkey,
              isDmChannel: isDmChannel,
              onSelect: insertMention,
            ),
          )
        : const SizedBox.shrink(key: ValueKey('no-suggestions'));
    Widget buildOverlayPanel(_AttachmentSurface surface) =>
        _buildComposeBarOverlayPanel(
          surface: surface,
          suggestionPanel: suggestionPanel,
          attachmentSurface: attachmentSurface,
          focusNode: focusNode,
          voiceNote: voiceNote,
          ref: ref,
          retainAndQueueImages: retainAndQueueImages,
          queueImages: queueImages,
          pickThenQueue: pickThenQueue,
          chooseAttachment: chooseAttachment,
        );

    // Suggestions and attachments live in the overlay so showing them cannot
    // reflow the composer. Both stay anchored just above the capsule.
    final hasPendingUploads = uploadingCount.value > 0;
    return _ComposerDockFrame(
      expansionAnimation: composerExpansionController,
      forceFullWidth: _voiceNoteFullWidth(voiceNote, attachments.value),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          _UploadProgressMotion(
            visible: hasPendingUploads,
            progress: uploadProgress.value,
            reducedMotion: reducedMotion,
            onCancel: () {
              activeUploadCancellation.value?.cancel();
              uploadGeneration.value += 1;
              uploadingCount.value = 0;
              uploadProgress.value = 0;
            },
          ),
          _ComposerOverlayPortal(
            controller: suggestionOverlayController,
            attachmentSurface: attachmentSurface,
            reducedMotion: reducedMotion,
            buildOverlayPanel: buildOverlayPanel,
            onDismissAttachmentSurface: () {
              attachmentSurface.value = _AttachmentSurface.closed;
            },
            child: _ComposeBarLayout(
              voiceNoteRecorder: voiceNote.recorder,
              attachments: attachments.value,
              onRemoveAttachment: removeAttachment,
              uploadError: uploadError.value,
              isExpanded: isComposerExpanded.value,
              controller: controller,
              focusNode: focusNode,
              contextMenuBuilder: buildContextMenu,
              onContentInserted: uploadPastedImage,
              onSend: () => unawaited(send()),
              resolvedHint: resolvedHint,
              attachmentSurface: attachmentSurface.value,
              onAttachmentTap: handleAttachmentTap,
              onExpand: expandComposer,
              expansionValue: composerExpansionValue,
              expansionProgress: composerExpansionProgress,
              formattingOpen: showFormatting.value,
              onCloseFormatting: () => showFormatting.value = false,
              motionDuration: motionDuration,
              onFormat: applyFormat,
              onMention: () {
                attachmentSurface.value = _AttachmentSurface.closed;
                triggerMention();
              },
              onChannel: () {
                attachmentSurface.value = _AttachmentSurface.closed;
                triggerChannel();
              },
              onEmoji: () {
                attachmentSurface.value = _AttachmentSurface.closed;
                isEmojiPickerOpen.value = true;
                _showComposerEmojiPicker(context, insertEmoji, () {
                  if (!context.mounted) return;
                  isEmojiPickerOpen.value = false;
                  focusNode.requestFocus();
                });
              },
              onOpenFormatting: () {
                attachmentSurface.value = _AttachmentSurface.closed;
                showFormatting.value = true;
              },
              hasPendingUploads: hasPendingUploads,
              canSend: controller.text.trim().isNotEmpty || hasAttachments,
              isSending: isSending.value,
            ),
          ),
        ],
      ),
    );
  }
}
