import 'dart:ui' show SemanticsFlag;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/companion_terminal_presentation.dart';
import 'package:neoth_companion/companion_theme.dart';
import 'package:neoth_companion/models.dart';

void main() {
  testWidgets('TERM-PRES-001 maps all V3 outcomes without introducing actions', (tester) async {
    const outcomes = <String, String>{
      'accepted': 'Request completed', 'denied': 'NEOTH denied this request', 'busy': 'NEOTH is busy',
      'unavailable': 'NEOTH is unavailable', 'timeout': 'The request timed out', 'indeterminate': 'The request outcome is indeterminate',
    };
    for (final entry in outcomes.entries) {
      final terminal = CompanionChatTerminal(
        requestId: '00000000-0000-0000-0000-000000000001', outcome: entry.key,
        provider: entry.key == 'accepted' ? 'local-provider' : null, model: entry.key == 'accepted' ? 'neoth-model' : null, records: const [],
      );
      await tester.pumpWidget(_host(terminal));
      expect(find.text('Chat result: ${entry.key}'), findsOneWidget);
      expect(find.text(entry.value), findsOneWidget);
      expect(find.byType(FilledButton), findsNothing);
      expect(find.byType(OutlinedButton), findsNothing);
    }
  });

  testWidgets('TERM-PRES-002 renders each allowed record kind with text accessible once', (tester) async {
    const terminal = CompanionChatTerminal(
      requestId: '00000000-0000-0000-0000-000000000001', outcome: 'accepted', provider: 'local-provider', model: 'neoth-model',
      records: [
        CompanionChatRecord(kind: 'stdout', text: 'A bounded reply.'),
        CompanionChatRecord(kind: 'stderr', text: 'A bounded diagnostic.'),
        CompanionChatRecord(kind: 'notice', text: ''),
      ],
    );
    final semantics = tester.ensureSemantics();
    try {
      await tester.pumpWidget(_host(terminal));
      expect(find.text('Response output'), findsOneWidget);
      expect(find.text('Diagnostic output'), findsOneWidget);
      expect(find.text('NEOTH notice'), findsOneWidget);
      expect(find.text('A bounded reply.'), findsOneWidget);
      expect(find.text('Provider: local-provider'), findsOneWidget);
      expect(find.bySemanticsLabel('Response output'), findsOneWidget);
      final replyNodes = find.semantics.byValue('A bounded reply.').evaluate().toList();
      expect(replyNodes, hasLength(1));
      expect(replyNodes.single.getSemanticsData().hasFlag(SemanticsFlag.isReadOnly), isTrue);
      expect(find.bySemanticsLabel('A bounded reply.'), findsNothing);
      expect(find.byType(FilledButton), findsNothing);
      expect(find.byType(OutlinedButton), findsNothing);
    } finally {
      semantics.dispose();
    }
  });

  testWidgets('TERM-PRES-003 keeps a nonaccepted terminal private and non-retrying', (tester) async {
    const terminal = CompanionChatTerminal(requestId: '00000000-0000-0000-0000-000000000002', outcome: 'denied', records: []);
    await tester.pumpWidget(_host(terminal));
    expect(find.text('Chat result: denied'), findsOneWidget);
    expect(find.text('NEOTH denied this request'), findsOneWidget);
    expect(find.text('No message is retried automatically.'), findsOneWidget);
    expect(find.textContaining('Provider:'), findsNothing);
    expect(find.textContaining('Model:'), findsNothing);
    expect(find.byType(FilledButton), findsNothing);
    expect(find.byType(OutlinedButton), findsNothing);
  });

  testWidgets('TERM-PRES-004 preserves narrow high-scale terminal semantics', (tester) async {
    tester.view.physicalSize = const Size(480, 1600);
    tester.view.devicePixelRatio = 2;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final longRecord = List.filled(128, 'bounded terminal text').join(' ');
    final terminal = CompanionChatTerminal(
      requestId: '00000000-0000-0000-0000-000000000003', outcome: 'accepted', provider: 'local-provider', model: 'neoth-model',
      records: [CompanionChatRecord(kind: 'notice', text: longRecord)],
    );
    final semantics = tester.ensureSemantics();
    try {
      await tester.pumpWidget(_host(terminal, textScaler: const TextScaler.linear(2), scrollable: true));
      expect(tester.getSize(find.byType(Scaffold)).width, 240);
      expect(tester.getSize(find.byType(CompanionTerminalCard)).width, lessThanOrEqualTo(240));
      expect(MediaQuery.textScalerOf(tester.element(find.byType(CompanionTerminalCard))).scale(1), 2);
      expect(find.bySemanticsLabel('NEOTH notice'), findsOneWidget);
      final replyNodes = find.semantics.byValue(longRecord).evaluate().toList();
      expect(replyNodes, hasLength(1));
      expect(replyNodes.single.getSemanticsData().hasFlag(SemanticsFlag.isReadOnly), isTrue);
      expect(find.bySemanticsLabel(longRecord), findsNothing);
      expect(tester.takeException(), isNull);
    } finally {
      semantics.dispose();
    }
  });
}

Widget _host(
  CompanionChatTerminal terminal, {
  TextScaler? textScaler,
  bool scrollable = false,
}) => MaterialApp(
      theme: CompanionTheme.neothDark(),
      builder: textScaler == null
          ? null
          : (context, child) => MediaQuery(
                data: MediaQuery.of(context).copyWith(textScaler: textScaler),
                child: child!,
              ),
      home: Scaffold(
        body: scrollable
            ? ListView(children: [CompanionTerminalCard(terminal: terminal)])
            : CompanionTerminalCard(terminal: terminal),
      ),
    );
