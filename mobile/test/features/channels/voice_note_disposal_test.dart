import 'dart:async';
import 'dart:io';

import 'package:buzz/features/channels/voice_note_composer_recorder.dart';
import 'package:buzz/features/channels/voice_note_recording.dart';
import 'package:buzz/shared/audio/microphone_capture.dart';
import 'package:buzz/shared/relay/app_lifecycle_provider.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:record/record.dart';

class _Lifecycle extends AppLifecycleNotifier {
  @override
  AppLifecycleState build() => AppLifecycleState.resumed;
}

class _Backend implements VoiceNoteRecorderBackend {
  final disposal = Completer<void>();
  final disposalStarted = Completer<void>();
  final amplitudes = StreamController<Amplitude>.broadcast();
  int cancelCalls = 0;
  int disposeCalls = 0;
  int startCalls = 0;
  bool failCancel = true;

  @override
  Future<bool> hasPermission() async => true;

  @override
  Future<void> start(RecordConfig config, {required String path}) async {
    startCalls += 1;
  }

  @override
  Stream<Amplitude> onAmplitudeChanged(Duration interval) => amplitudes.stream;

  @override
  Future<String?> stop() async => '/tmp/finalized-voice-note.m4a';

  @override
  Future<void> cancel() async {
    cancelCalls += 1;
    if (failCancel) throw StateError('native cancellation failed');
  }

  @override
  Future<void> dispose() async {
    disposeCalls += 1;
    disposalStarted.complete();
    try {
      await disposal.future;
    } finally {
      await amplitudes.close();
    }
  }
}

DeviceVoiceNoteRecorder _recorder(_Backend backend) => DeviceVoiceNoteRecorder(
  backend: backend,
  temporaryDirectory: () async => Directory.systemTemp,
);

void main() {
  test(
    'repeated cancellation failure still disposes and closes levels',
    () async {
      final backend = _Backend()..disposal.complete();
      final recorder = _recorder(backend);
      final levelsClosed = recorder.levels.drain<void>();
      await recorder.start();
      await expectLater(recorder.cancel(), throwsStateError);

      await recorder.dispose();
      await levelsClosed;
      await recorder.dispose();
      expect(backend.cancelCalls, 2);
      expect(backend.disposeCalls, 1);
    },
  );

  test('all dispose callers wait for the same native release', () async {
    final backend = _Backend()..failCancel = false;
    final recorder = _recorder(backend);
    await recorder.start();
    final first = recorder.dispose();
    await backend.disposalStarted.future;
    final second = recorder.dispose();
    var completed = false;
    unawaited(second.then((_) => completed = true));
    await Future<void>.delayed(Duration.zero);
    expect(completed, isFalse);
    expect(identical(first, second), isTrue);

    backend.disposal.complete();
    await Future.wait([first, second]);
    await recorder.cancel();
    await recorder.dispose();
    expect(backend.cancelCalls, 1);
    expect(backend.disposeCalls, 1);
  });

  for (final failCancel in [false, true]) {
    test(
      'native disposal failure stays observable (cancel=$failCancel)',
      () async {
        final backend = _Backend()..failCancel = failCancel;
        final recorder = _recorder(backend);
        final levelsClosed = recorder.levels.drain<void>();
        await recorder.start();
        final first = recorder.dispose();
        final second = recorder.dispose();
        final failure = StateError('native disposal failed');
        final firstError = expectLater(first, throwsA(same(failure)));
        final secondError = expectLater(second, throwsA(same(failure)));
        await backend.disposalStarted.future;
        backend.disposal.completeError(failure);
        await Future.wait([firstError, secondError]);
        await levelsClosed;
        await expectLater(recorder.dispose(), throwsA(same(failure)));
        expect(backend.disposeCalls, 1);
      },
    );
  }

  test(
    'successful stop result survives disposal without cancellation',
    () async {
      final backend = _Backend()..disposal.complete();
      final recorder = _recorder(backend);
      await recorder.start();
      final recording = await recorder.stop();
      await recorder.dispose();
      expect(recording.file.path, '/tmp/finalized-voice-note.m4a');
      expect(backend.cancelCalls, 0);
      expect(backend.disposeCalls, 1);
    },
  );

  for (final failDispose in [false, true]) {
    testWidgets(
      'composer lease follows actual release after cancel errors (dispose fails=$failDispose)',
      (tester) async {
        final backend = _Backend();
        final recorder = _recorder(backend);
        final container = ProviderContainer(
          overrides: [
            appLifecycleProvider.overrideWith(_Lifecycle.new),
            voiceNoteRecorderFactoryProvider.overrideWithValue(() => recorder),
          ],
        );
        addTearDown(container.dispose);
        final visible = ValueNotifier(true);
        addTearDown(visible.dispose);
        await tester.pumpWidget(
          UncontrolledProviderScope(
            container: container,
            child: MaterialApp(
              home: Scaffold(
                body: ValueListenableBuilder(
                  valueListenable: visible,
                  builder: (context, shown, _) => shown
                      ? VoiceNoteComposerRecorder(
                          onCancel: () => visible.value = false,
                          onRecorded: (_) =>
                              fail('Cancellation created a draft'),
                        )
                      : const SizedBox.shrink(),
                ),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        expect(
          find.byKey(const ValueKey('voice-note-recorder-error')),
          findsNothing,
        );
        expect(backend.startCalls, 1);
        final microphone = container.read(microphoneCaptureProvider);
        expect(microphone.acquire(), isNull);
        await tester.tap(
          find.byKey(const ValueKey('voice-note-recorder-close')),
        );
        await tester.pumpAndSettle();
        for (var i = 0; i < 10 && backend.disposeCalls == 0; i += 1) {
          await tester.runAsync(() => Future<void>.delayed(Duration.zero));
          await tester.pump();
        }
        expect(visible.value, isFalse);
        expect(find.byType(VoiceNoteComposerRecorder), findsNothing);
        expect(backend.cancelCalls, greaterThan(0));
        expect(backend.disposeCalls, 1);
        expect(microphone.acquire(), isNull);

        if (failDispose) {
          backend.disposal.completeError(StateError('native disposal failed'));
        } else {
          backend.disposal.complete();
        }
        await tester.runAsync(() async {
          try {
            await recorder.dispose();
          } catch (_) {
            // The assertions below check the retained lease on native failure.
          }
        });
        await tester.pumpAndSettle();
        final release = microphone.acquire();
        expect(release, failDispose ? isNull : isNotNull);
        release?.call();
        expect(tester.takeException(), isNull);
        expect(backend.disposeCalls, 1);
      },
    );
  }
}
