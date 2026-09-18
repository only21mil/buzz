import 'package:buzz/features/channels/channel.dart';
import 'package:buzz/features/channels/dm_channel_labels.dart';
import 'package:buzz/shared/identity/npub.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const self =
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const other =
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

  Channel dmChannel({
    required List<String> pubkeys,
    List<String> participants = const [],
  }) {
    return Channel(
      id: 'dm1',
      name: 'DM',
      channelType: 'dm',
      visibility: 'private',
      description: '',
      createdBy: self,
      createdAt: DateTime(2025),
      memberCount: pubkeys.length,
      isMember: true,
      participantPubkeys: pubkeys,
      participants: participants,
    );
  }

  test(
    'resolveDmChannelDisplayLabel uses compact npub for unnamed counterpart',
    () {
      final channel = dmChannel(pubkeys: [self, other]);
      expect(
        resolveDmChannelDisplayLabel(channel, currentPubkey: self),
        truncateNpub(other),
      );
    },
  );

  test('dmAvatarInitial keys unnamed counterpart to hex not npub', () {
    final channel = dmChannel(pubkeys: [self, other]);
    expect(dmAvatarInitial(channel, currentPubkey: self), 'B');
  });
}
