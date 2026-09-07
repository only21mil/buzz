part of '../animated_avatar_capture.dart';

/// Creates an isolated workspace for one capture's frames.
@visibleForTesting
Future<Directory> createAnimatedAvatarFrameDirectory({
  Directory? parent,
}) async => (parent ?? await getTemporaryDirectory()).createTemp(
  'buzz-avatar-capture-',
);

/// Encodes one poster frame for validating animated-avatar framing parity.
@visibleForTesting
Uint8List encodeAnimatedAvatarPoster({
  required Uint8List frame,
  required double scale,
}) => _encodeAvatar(
  _EncodeRequest(
    frames: [frame],
    posterIndex: 0,
    scale: scale,
    offsetX: 0,
    offsetY: 0,
    backdropColor: 0xff0000ff,
    personOutline: false,
    shapeScale: 1,
    shapeOffsetX: 0,
    shapeOffsetY: 0,
  ),
).poster;
