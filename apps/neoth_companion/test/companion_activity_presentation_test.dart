import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/companion_activity_presentation.dart';
import 'package:neoth_companion/companion_theme.dart';
import 'package:neoth_companion/models.dart';

void main() {
  const snapshot = CompanionChatActivitySnapshot(
    requestId: '11111111-1111-1111-1111-111111111111', maxEventSeq: 2, incomplete: true,
    events: [CompanionToolActivityEvent(eventSeq: 1, ordinal: 1, phase: CompanionToolActivityPhase.started, label: 'Read file'), CompanionToolActivityEvent(eventSeq: 2, ordinal: 2, phase: CompanionToolActivityPhase.succeeded, label: 'Read file')],
  );
  testWidgets('ACTIVITY-PRES-001 is passive, redacted, and accessible', (tester) async {
    await tester.pumpWidget(MaterialApp(theme: CompanionTheme.neothDark(), home: const Scaffold(body: CompanionActivityCard(snapshot: snapshot))));
    expect(find.text('NEOTH activity'), findsOneWidget);
    expect(find.text('Some updates may be missing.'), findsOneWidget);
    expect(find.text('Read file'), findsNWidgets(2));
    expect(find.textContaining('11111111'), findsNothing);
    expect(find.byType(FilledButton), findsNothing);
    expect(find.byType(OutlinedButton), findsNothing);
  });
  testWidgets('ACTIVITY-PRES-002 remains bounded at 2x text scale', (tester) async {
    tester.view.physicalSize = const Size(480, 1600); tester.view.devicePixelRatio = 2;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(MaterialApp(theme: CompanionTheme.neothDark(), builder: (context, child) => MediaQuery(data: MediaQuery.of(context).copyWith(textScaler: const TextScaler.linear(2)), child: child!), home: Scaffold(body: ListView(children: const [CompanionActivityCard(snapshot: snapshot)]))));
    expect(tester.getSize(find.byType(CompanionActivityCard)).width, lessThanOrEqualTo(240));
    expect(tester.takeException(), isNull);
  });

  testWidgets('ACTIVITY-PRES-003 collapses one tool ordinal to its latest public phase', (tester) async {
    const compact = CompanionChatActivitySnapshot(requestId: '11111111-1111-1111-1111-111111111111', maxEventSeq: 2, incomplete: false, events: [
      CompanionToolActivityEvent(eventSeq: 1, ordinal: 1, phase: CompanionToolActivityPhase.started, label: 'Read file'),
      CompanionToolActivityEvent(eventSeq: 2, ordinal: 1, phase: CompanionToolActivityPhase.succeeded, label: 'Read file'),
    ]);
    await tester.pumpWidget(MaterialApp(theme: CompanionTheme.neothDark(), home: const Scaffold(body: CompanionActivityCard(snapshot: compact))));
    expect(find.text('Read file'), findsOneWidget);
    expect(find.text('Completed'), findsOneWidget);
    expect(find.text('Started'), findsNothing);
  });

  testWidgets('ACTIVITY-PRES-004 exposes an unknown public outcome visibly', (tester) async {
    const unknown = CompanionChatActivitySnapshot(requestId: '11111111-1111-1111-1111-111111111111', maxEventSeq: 1, incomplete: false, events: [CompanionToolActivityEvent(eventSeq: 1, ordinal: 1, phase: CompanionToolActivityPhase.unknown, label: 'Tool call')]);
    await tester.pumpWidget(MaterialApp(theme: CompanionTheme.neothDark(), home: const Scaffold(body: CompanionActivityCard(snapshot: unknown))));
    expect(find.text('Tool call'), findsOneWidget);
    expect(find.text('Outcome unknown'), findsOneWidget);
    expect(find.text('Updated'), findsNothing);
  });
}
