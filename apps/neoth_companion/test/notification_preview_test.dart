import 'dart:async';
import 'dart:ui' as ui show SemanticsFlag;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/notification_preview_controller.dart';
import 'package:neoth_companion/notification_preview_panel.dart';
import 'package:neoth_companion/companion_theme.dart';

class PreviewFixture {
  PreviewFixture(this.tester, {bool supported = true}) {
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      if (call.method == 'configure') {
        final args = Map<String, dynamic>.from(call.arguments as Map);
        scope = args['scope'] as String;
        if (held != null) { final response = held!; held = null; return response.future; }
        return <String, dynamic>{'scope': scope, 'access': access};
      }
      if (call.method == 'openSettings') return null;
      throw MissingPluginException();
    });
    controller = NotificationPreviewController(channel: channel, supported: supported, now: () => now);
  }
  final WidgetTester tester;
  static const channel = MethodChannel('neoth_companion/notification_preview_test');
  late final NotificationPreviewController controller;
  DateTime now = DateTime(2026, 10, 9, 12);
  bool access = true;
  String scope = '';
  Completer<Map<String, dynamic>>? held;
  final calls = <MethodCall>[];

  Future<void> enable() async {
    await controller.setVisible(true);
    await controller.setPackage('com.whatsapp', true);
    await controller.setEnabled(true);
  }

  Map<String, dynamic> event({String? source, String package = 'com.whatsapp', int age = 0}) {
    final posted = now.millisecondsSinceEpoch - age;
    return <String, dynamic>{'scope': scope, 'source': source ?? 'a' * 64, 'package': package,
      'channel': previewPackages[package], 'sender': 'A sender', 'text': 'An incoming message',
      'postedAt': posted, 'expiresAt': posted + 30000};
  }

  Future<void> deliver(Map<String, dynamic> value, {String method = 'preview'}) async {
    await tester.binding.defaultBinaryMessenger.handlePlatformMessage(channel.name,
      const StandardMethodCodec().encodeMethodCall(MethodCall(method, value)), (_) {});
  }

  void dispose() {
    controller.dispose();
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, null);
  }
}

void main() {
  testWidgets('JM07 default off explicit package and system access all gate previews', (tester) async {
    final f = PreviewFixture(tester); addTearDown(f.dispose);
    await f.controller.setVisible(true);
    await f.deliver(f.event()); expect(f.controller.current, isNull);
    await f.controller.setEnabled(true);
    await f.deliver(f.event()); expect(f.controller.current, isNull);
    f.access = false;
    await f.controller.setPackage('com.whatsapp', true);
    await f.deliver(f.event()); expect(f.controller.current, isNull);
    f.access = true;
    await f.controller.setVisible(true);
    await f.deliver(f.event()); expect(f.controller.current?.text, 'An incoming message');
    expect(f.calls.every((call) => call.method == 'configure'), isTrue);
    f.controller.dispose();
  });

  testWidgets('JM07 duplicate delivery and dismissal cannot restart a preview deadline', (tester) async {
    final f = PreviewFixture(tester); addTearDown(f.dispose); await f.enable();
    final event = f.event(); await f.deliver(event);
    f.controller.dismiss(); expect(f.controller.current, isNull);
    f.now = f.now.add(const Duration(seconds: 1));
    await f.deliver(event); expect(f.controller.current, isNull);
    await f.deliver(f.event(source: 'b' * 64)); expect(f.controller.current, isNotNull);
    f.controller.dispose();
  });

  testWidgets('JM07 delayed delivery expires at the original thirty second boundary', (tester) async {
    final f = PreviewFixture(tester); addTearDown(f.dispose); await f.enable();
    await f.deliver(f.event(age: 20000)); expect(f.controller.current, isNotNull);
    await tester.pump(const Duration(milliseconds: 9999)); expect(f.controller.current, isNotNull);
    await tester.pump(const Duration(milliseconds: 1)); expect(f.controller.current, isNull);
  });

  testWidgets('JM07 background consent changes and old scopes clear without replay', (tester) async {
    final f = PreviewFixture(tester); addTearDown(f.dispose); await f.enable();
    final old = f.event(); await f.deliver(old);
    await f.controller.setVisible(false); expect(f.controller.current, isNull);
    await f.deliver(old); expect(f.controller.current, isNull);
    await f.controller.setVisible(true);
    await f.deliver(old); expect(f.controller.current, isNull);
    await f.deliver(f.event(source: 'b' * 64)); expect(f.controller.current, isNotNull);
    await f.controller.setPackage('com.whatsapp', false); expect(f.controller.current, isNull);
    await f.deliver(f.event(source: 'c' * 64)); expect(f.controller.current, isNull);
  });

  testWidgets('JM07 malformed foreign stale future and action bearing events are rejected', (tester) async {
    final f = PreviewFixture(tester); addTearDown(f.dispose); await f.enable();
    for (final event in <Map<String, dynamic>>[
      f.event(package: 'com.whatsapp.w4b'), f.event(package: 'org.telegram.messenger'),
      f.event(age: 30000), f.event(age: -1), {...f.event(), 'source': 'raw-notification-key'},
      {...f.event(), 'text': 'x' * 513}, {...f.event(), 'sender': 'x' * 81},
      {...f.event(), 'action': 'reply'}, {...f.event(), 'channel': 'NEOTH'},
      {...f.event(), 'expiresAt': f.now.millisecondsSinceEpoch + 30001},
    ]) { await f.deliver(event); expect(f.controller.current, isNull); }
    await f.deliver({...f.event(), 'text': '🙂' * 512}); expect(f.controller.current, isNotNull);
    f.controller.dispose();
  });

  testWidgets('JM07 quiet hours reject overnight and remove a card at quiet start', (tester) async {
    final f = PreviewFixture(tester); addTearDown(f.dispose); await f.enable();
    await f.controller.setQuietHours(enabled: true, start: 22 * 60, end: 7 * 60);
    f.now = DateTime(2026, 10, 9, 23);
    await f.deliver(f.event()); expect(f.controller.current, isNull);
    f.now = DateTime(2026, 10, 10, 6, 59);
    await f.deliver(f.event()); expect(f.controller.current, isNull);
    f.now = DateTime(2026, 10, 10, 7);
    await f.deliver(f.event()); expect(f.controller.current, isNotNull);
    f.now = DateTime(2026, 10, 10, 21, 59, 59);
    await f.deliver(f.event(source: 'b' * 64)); expect(f.controller.current, isNotNull);
    await tester.pump(const Duration(seconds: 1)); expect(f.controller.current, isNull);
  });

  testWidgets('JM07 delayed configuration cannot restore access after disable or disposal', (tester) async {
    final f = PreviewFixture(tester); addTearDown(f.dispose); await f.enable();
    final first = Completer<Map<String, dynamic>>(); f.held = first;
    final waiting = f.controller.setVisible(true);
    await tester.pump(); final oldScope = f.scope;
    await f.controller.setEnabled(false);
    first.complete({'scope': oldScope, 'access': true}); await waiting;
    expect(f.controller.active, isFalse);
    final second = Completer<Map<String, dynamic>>(); f.held = second;
    final after = f.controller.setEnabled(true);
    await tester.pump(); final disposedScope = f.scope;
    f.controller.dispose();
    second.complete({'scope': disposedScope, 'access': true}); await after;
    expect(f.controller.current, isNull); expect(tester.takeException(), isNull);
  });

  testWidgets('JM07 platform revocation removes data and requires new explicit consent', (tester) async {
    final f = PreviewFixture(tester); addTearDown(f.dispose); await f.enable();
    await f.deliver(f.event()); expect(f.controller.current, isNotNull);
    final old = f.event(source: 'b' * 64);
    f.access = false;
    await f.deliver({'scope': f.scope}, method: 'revoked');
    expect(f.controller.current, isNull); expect(f.controller.enabled, isFalse);
    await f.deliver(old); expect(f.controller.current, isNull);
  });

  testWidgets('JM07 iOS unsupported surface never requests Android notification access', (tester) async {
    final f = PreviewFixture(tester, supported: false); addTearDown(f.dispose);
    await f.enable(); await f.controller.openSystemSettings();
    expect(f.controller.active, isFalse); expect(f.calls, isEmpty);
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: NotificationPreviewPanel(controller: f.controller))));
    expect(find.textContaining('only on Android'), findsOneWidget);
    expect(find.text('Open Android notification access'), findsNothing);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('JM07 notification access opens only after an explicit accessible settings tap', (tester) async {
    final f = PreviewFixture(tester); addTearDown(f.dispose); f.access = false;
    final semantics = tester.ensureSemantics();
    try {
      await tester.pumpWidget(MaterialApp(theme: CompanionTheme.neothDark(), home: Scaffold(
        body: SingleChildScrollView(child: NotificationPreviewPanel(controller: f.controller)),
      )));
      await f.controller.setVisible(true); await tester.pump();
      expect(find.text('Open Android notification access'), findsNothing);
      expect(f.calls.where((call) => call.method == 'openSettings'), isEmpty);
      await tester.tap(find.text('Show previews while NEOTH is open')); await tester.pumpAndSettle();
      expect(f.controller.enabled, isTrue); expect(f.controller.packages, isEmpty);
      expect(find.byType(CheckboxListTile), findsNWidgets(3));
      expect(f.calls.where((call) => call.method == 'openSettings'), isEmpty);
      final button = find.widgetWithText(OutlinedButton, 'Open Android notification access');
      await tester.ensureVisible(button); await tester.pumpAndSettle();
      expect(tester.getSemantics(button).hasFlag(ui.SemanticsFlag.isButton), isTrue);
      await tester.tap(button); await tester.pump();
      expect(f.calls.where((call) => call.method == 'openSettings'), hasLength(1));
      await tester.ensureVisible(find.text('WhatsApp Business'));
      await tester.tap(find.text('WhatsApp Business')); await tester.pumpAndSettle();
      expect(f.controller.packages, {'com.whatsapp.w4b'});
      expect(f.calls.every((call) => call.method == 'configure' || call.method == 'openSettings'), isTrue);
      await tester.pumpWidget(const SizedBox());
      expect(tester.takeException(), isNull);
    } finally { semantics.dispose(); }
  });

  testWidgets('JM07 preview stays readable at narrow large text without a reply action', (tester) async {
    final f = PreviewFixture(tester); addTearDown(f.dispose);
    tester.view.physicalSize = const Size(240, 1200); tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(MaterialApp(theme: CompanionTheme.neothDark(), home: MediaQuery(
      data: const MediaQueryData(textScaler: TextScaler.linear(2)),
      child: Scaffold(body: SingleChildScrollView(child: NotificationPreviewPanel(controller: f.controller))),
    )));
    await f.enable(); await f.deliver(f.event()); await tester.pump();
    await tester.ensureVisible(find.text('An incoming message')); await tester.pumpAndSettle();
    expect(find.text('An incoming message'), findsOneWidget);
    expect(find.text('Reply'), findsNothing); expect(find.text('Send'), findsNothing);
    await tester.ensureVisible(find.text('Hide preview')); await tester.tap(find.text('Hide preview')); await tester.pump();
    expect(find.text('An incoming message'), findsNothing); expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });
}