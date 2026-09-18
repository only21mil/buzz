part of '../compose_bar.dart';

void _clearComposeBar({
  required ObjectRef<int> draftRevision,
  required _MarkdownEditingController controller,
  required ValueNotifier<List<_PendingAttachment>> attachments,
  required ObjectRef<Map<String, MentionCandidate>> mentionMap,
  required ValueNotifier<String?> mentionQuery,
  required ValueNotifier<String?> channelQuery,
  required ValueNotifier<_AttachmentSurface> attachmentSurface,
  required ValueNotifier<bool> showFormatting,
  required ValueNotifier<String?> uploadError,
  required FocusNode focusNode,
}) {
  draftRevision.value += 1;
  controller.clear();
  attachments.value = [];
  mentionMap.value.clear();
  mentionQuery.value = null;
  channelQuery.value = null;
  attachmentSurface.value = _AttachmentSurface.closed;
  showFormatting.value = false;
  uploadError.value = null;
  focusNode.requestFocus();
}

Future<void> _sendComposeBarMessage({
  required BuildContext context,
  required WidgetRef ref,
  required String channelId,
  required ComposeBarOnSend onSend,
  required _MarkdownEditingController controller,
  required ValueNotifier<List<_PendingAttachment>> attachments,
  required ObjectRef<Map<String, MentionCandidate>> mentionMap,
  required ValueNotifier<bool> isSending,
  required ValueNotifier<int> uploadingCount,
  required ValueNotifier<double> uploadProgress,
  required ObjectRef<int> uploadGeneration,
  required ObjectRef<UploadCancellationToken?> activeUploadCancellation,
  required ObjectRef<int> draftRevision,
  required ValueNotifier<String?> uploadError,
  required FocusNode focusNode,
  required bool hasAttachments,
  required AsyncValue<List<ChannelMember>> membersAsync,
  required List<AgentDirectoryEntry>? relayAgents,
  required Map<String, String>? agentOwners,
  required List<Channel> channels,
  required Map<String, UserProfile> userCache,
  required String? currentPubkey,
  required List<CustomEmoji> customEmoji,
  required VoidCallback clearComposer,
}) async {
  final text = controller.text.trim();
  if ((text.isEmpty && !hasAttachments) ||
      isSending.value ||
      uploadingCount.value > 0) {
    return;
  }
  // Resolved before any await: see `_reportSendCancelledByCommunitySwitch`.
  final messenger = ScaffoldMessenger.maybeOf(context);

  List<MentionCandidate> selectedMentions;
  try {
    selectedMentions = _resolveComposerMentions(
      text,
      mentionMap.value,
      buildMentionCandidates(
        members: membersAsync.asData?.value ?? const <ChannelMember>[],
        relayAgents: const [],
        sharedChannelIds: const {},
        userCache: userCache,
        ownerByAgentPubkey: agentOwners ?? const {},
      ),
      buildMentionCandidates(
        members: membersAsync.asData?.value ?? const [],
        relayAgents: relayAgents ?? const [],
        sharedChannelIds: {
          for (final c in channels)
            if (c.isMember && !c.isArchived) c.id,
        },
        userCache: userCache,
        ownerByAgentPubkey: agentOwners ?? const {},
        currentPubkey: currentPubkey,
        searchResults: [
          for (final c in mentionMap.value.values)
            if (c.requiresRevalidation &&
                userCache[c.pubkey.toLowerCase()] != null)
              userCache[c.pubkey.toLowerCase()]!,
        ],
      ),
    );
  } on FormatException catch (error) {
    messenger?.showSnackBar(SnackBar(content: Text(error.message)));
    return;
  }
  final outgoing = _OutgoingMentions(selectedMentions);
  final scan = await _scanNonMemberMentions(
    ref,
    channelId: channelId,
    selectedMentions: selectedMentions,
    currentPubkey: currentPubkey,
  );

  if (scan.humans.isNotEmpty) {
    if (!context.mounted) return;
    final choice = await _promptNonMemberMention(
      context,
      names: [for (final candidate in scan.humans) candidate.label],
      canInvite: scan.canAddMembers,
    );
    if (choice == null) return;
    outgoing.resolveHumanChoice(choice, scan.humans);
  }

  final queuedAttachments = List<_PendingAttachment>.of(attachments.value);
  final channelActions = ref.read(channelActionsProvider);

  Future<void> addMentionedNonMembers() =>
      outgoing.addNonMembers(channelActions, scan: scan, messenger: messenger);

  isSending.value = true;
  try {
    if (queuedAttachments.isEmpty) {
      try {
        await addMentionedNonMembers();
        final payload = _ComposeDraftPayload.fromDraft(
          text: text,
          attachments: const [],
          customEmoji: customEmoji,
        );
        await onSend(
          payload.content,
          outgoing.pubkeys,
          mediaTags: [...payload.mediaTags, ...outgoing.referenceTags],
        );
        if (context.mounted) clearComposer();
      } on StateError {
        _reportSendCancelledByCommunitySwitch(messenger);
      } catch (error) {
        messenger?.showSnackBar(
          SnackBar(content: Text(_composeSendErrorMessage(error))),
        );
      }
      return;
    }

    final draftText = controller.value;
    final draftAttachments = List<_PendingAttachment>.of(attachments.value);
    final draftMentions = Map<String, MentionCandidate>.of(mentionMap.value);
    clearComposer();
    final clearedDraftRevision = draftRevision.value;
    uploadingCount.value += 1;
    uploadProgress.value = 0;
    isSending.value = false;
    final queueGeneration = uploadGeneration.value;
    final cancellation = UploadCancellationToken();
    final uploadService = ref.read(mediaUploadServiceProvider);
    activeUploadCancellation.value = cancellation;
    final delivery = onSend;
    unawaited(() async {
      var retainedForRetry = false;
      try {
        final uploaded = <BlobDescriptor>[];
        for (var index = 0; index < queuedAttachments.length; index++) {
          final attachment = queuedAttachments[index];
          final descriptor = await _uploadPendingAttachment(
            uploadService,
            attachment,
            onProgress: (progress) {
              if (context.mounted) {
                uploadProgress.value =
                    (index + progress) / queuedAttachments.length;
              }
            },
            cancellationToken: cancellation,
          );
          if (queueGeneration != uploadGeneration.value) return;
          uploaded.add(descriptor);
          if (context.mounted) {
            uploadProgress.value = (index + 1) / queuedAttachments.length;
          }
        }
        final payload = _ComposeDraftPayload.fromDraft(
          text: text,
          attachments: uploaded,
          customEmoji: customEmoji,
        );
        if (queueGeneration != uploadGeneration.value) return;
        await addMentionedNonMembers();
        if (queueGeneration != uploadGeneration.value) return;
        await delivery(
          payload.content,
          outgoing.pubkeys,
          mediaTags: [...payload.mediaTags, ...outgoing.referenceTags],
        );
      } catch (error) {
        if (cancellation.isCancelled) return;
        if (context.mounted) uploadError.value = _formatUploadError(error);
        if (context.mounted &&
            queueGeneration == uploadGeneration.value &&
            draftRevision.value == clearedDraftRevision) {
          attachments.value = draftAttachments;
          retainedForRetry = true;
          mentionMap.value
            ..clear()
            ..addAll(draftMentions);
          controller.value = draftText;
          focusNode.requestFocus();
        }
      } finally {
        if (!retainedForRetry) {
          await _deleteOwnedAttachments(queuedAttachments);
        }
        if (activeUploadCancellation.value == cancellation) {
          activeUploadCancellation.value = null;
        }
        if (context.mounted && queueGeneration == uploadGeneration.value) {
          uploadingCount.value = math.max(0, uploadingCount.value - 1);
        }
      }
    }());
  } finally {
    if (context.mounted && isSending.value) isSending.value = false;
  }
}
