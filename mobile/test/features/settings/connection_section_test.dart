import 'package:buzz/features/settings/settings_page.dart';
import 'package:buzz/shared/community/community.dart';
import 'package:buzz/shared/community/community_provider.dart';
import 'package:buzz/shared/theme/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hooks_riverpod/hooks_riverpod.dart';
import 'package:lucide_icons_flutter/lucide_icons.dart';
import 'package:nostr/nostr.dart' as nostr;
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  testWidgets('exposes full npub in identity row semantics', (tester) async {
    SharedPreferences.setMockInitialValues({});
    final prefs = await SharedPreferences.getInstance();
    const privHex =
        '1111111111111111111111111111111111111111111111111111111111111111';
    const expectedNpub =
        'npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9';
    final community = Community.create(
      name: 'Team',
      relayUrl: 'wss://relay.example',
      nsec: nostr.Nip19.encode(
        prefix: nostr.Nip19Prefix.nsec,
        data: privHex,
      ),
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          savedPrefsProvider.overrideWithValue(prefs),
          activeCommunityProvider.overrideWith((ref) async => community),
        ],
        child: MaterialApp(
          theme: AppTheme.light(),
          home: SettingsPage(
            profileHeader: const SizedBox.shrink(),
            invitePageBuilder: (_) => const SizedBox.shrink(),
            identityRecoveryPageBuilder: (_) => const SizedBox.shrink(),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    final expectedPubkey = nostr.Keys(privHex).public;
    expect(find.text(expectedPubkey), findsNothing);
    expect(find.text(expectedNpub), findsNothing);
    await tester.scrollUntilVisible(
      find.text('Identity (pubkey)'),
      200,
      scrollable: find.byType(Scrollable).first,
    );
    expect(
      find.ancestor(
        of: find.text('Identity (pubkey)'),
        matching: find.byWidgetPredicate(
          (widget) =>
              widget is Semantics && widget.properties.value == expectedNpub,
        ),
      ),
      findsOneWidget,
    );

    expect(find.byIcon(LucideIcons.copy), findsOneWidget);
  });
}
