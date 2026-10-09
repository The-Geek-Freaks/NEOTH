import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/conversation_models.dart';
import 'package:neoth_companion/conversation_presentation.dart';
import 'package:neoth_companion/companion_terminal_presentation.dart';
import 'package:neoth_companion/companion_theme.dart';
import 'package:neoth_companion/models.dart';

void main() {
  viewportRegressionCases();
  testWidgets('JM05 canonical history renders one answer with narrow large text and explicit missing rows', (tester) async {
    tester.view.physicalSize = const Size(240, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final semantics = tester.ensureSemantics();
    try {
      const requestId = '00000000-0000-4000-8000-000000000011';
      const history = ConversationHistory(requestId: requestId, revision: 2,
        conversationId: '00000000-0000-4000-8000-000000000010', state: 'available', currentTurnCommitted: true,
        turns: [ConversationTurn(role: 'operator', text: 'ordinary message', truncated: false),
          ConversationTurn(role: 'agent', text: null, truncated: true),
          ConversationTurn(role: 'agent', text: 'visible reply', truncated: false)]);
      const terminal = CompanionChatTerminal(requestId: requestId, outcome: 'accepted',
        records: [CompanionChatRecord(kind: 'stdout', text: 'visible reply')], provider: 'provider-a', model: 'model-a');
      await tester.pumpWidget(MaterialApp(theme: CompanionTheme.neothDark(), home: MediaQuery(
        data: const MediaQueryData(textScaler: TextScaler.linear(2)),
        child: const Scaffold(body: SingleChildScrollView(child: Column(children: [
          ConversationHistoryCard(history: history), CompanionTerminalCard(terminal: terminal, recordsInHistory: true),
        ]))),
      )));
      expect(find.text('visible reply'), findsOneWidget);
      expect(find.text('ordinary message'), findsOneWidget);
      expect(find.textContaining('full text remains on NEOTH'), findsOneWidget);
      expect(find.textContaining('Older messages'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.ensureVisible(find.text('Model: model-a'));
      await tester.pumpAndSettle();
      expect(find.text('Model: model-a'), findsOneWidget);
      expect(tester.takeException(), isNull);
    } finally { semantics.dispose(); }
  });
}

Widget viewportFixture({required String scope, required int rows, double textScale = 1}) => MaterialApp(
  theme: CompanionTheme.neothDark(),
  home: MediaQuery(
    data: MediaQueryData(textScaler: TextScaler.linear(textScale)),
    child: Scaffold(body: Center(child: SizedBox(width: 240, child: ConversationViewport(
      scope: scope,
      revision: rows,
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        for (var index = 0; index < rows; index++)
          SizedBox(height: 64 * textScale, child: Text('Message $index')),
      ]),
    )))),
  ),
);

ScrollController viewportController(WidgetTester tester) => tester.widget<SingleChildScrollView>(
  find.byKey(const ValueKey('conversation-viewport-scroll'))).controller!;

void viewportRegressionCases() {
  testWidgets('JM05 viewport follows appended content while the reader is at the latest message', (tester) async {
    await tester.pumpWidget(viewportFixture(scope: 'a', rows: 12));
    await tester.pump();
    final scroll = viewportController(tester);
    expect(scroll.position.extentAfter, closeTo(0, 0.1));
    final before = scroll.offset;
    await tester.pumpWidget(viewportFixture(scope: 'a', rows: 16));
    await tester.pump();
    expect(scroll.offset, greaterThan(before));
    expect(scroll.position.extentAfter, closeTo(0, 0.1));
    await tester.pumpWidget(viewportFixture(scope: 'a', rows: 16, textScale: 2));
    await tester.pumpAndSettle();
    expect(scroll.position.extentAfter, closeTo(0, 0.1));
    expect(find.text('Following new messages'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('JM05 viewport preserves a reading position until the reader chooses latest', (tester) async {
    await tester.pumpWidget(viewportFixture(scope: 'a', rows: 16));
    await tester.pump();
    final scroll = viewportController(tester);
    await tester.drag(find.byKey(const ValueKey('conversation-viewport-scroll')), const Offset(0, 220));
    await tester.pumpAndSettle();
    expect(scroll.position.extentAfter, greaterThan(24));
    final reading = scroll.offset;
    expect(find.text('Jump to latest'), findsOneWidget);
    await tester.pumpWidget(viewportFixture(scope: 'a', rows: 20));
    await tester.pump();
    expect(scroll.offset, closeTo(reading, 0.1));
    await tester.tap(find.text('Jump to latest'));
    await tester.pump();
    await tester.pump();
    expect(scroll.position.extentAfter, closeTo(0, 0.1));
    expect(find.text('Following new messages'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('JM05 viewport resets following when the selected conversation changes', (tester) async {
    await tester.pumpWidget(viewportFixture(scope: 'a', rows: 16));
    await tester.pump();
    await tester.drag(find.byKey(const ValueKey('conversation-viewport-scroll')), const Offset(0, 220));
    await tester.pumpAndSettle();
    expect(find.text('Jump to latest'), findsOneWidget);
    await tester.pumpWidget(viewportFixture(scope: 'b', rows: 12));
    await tester.pump();
    expect(viewportController(tester).position.extentAfter, closeTo(0, 0.1));
    expect(find.text('Following new messages'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('JM05 viewport keeps large text controls usable and drops callbacks after disposal', (tester) async {
    final semantics = tester.ensureSemantics();
    try {
      await tester.pumpWidget(viewportFixture(scope: 'a', rows: 16, textScale: 2));
      await tester.pump();
      await tester.drag(find.byKey(const ValueKey('conversation-viewport-scroll')), const Offset(0, 220));
      await tester.pumpAndSettle();
      expect(find.text('Jump to latest'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.tap(find.text('Jump to latest'));
      await tester.pumpWidget(const SizedBox());
      await tester.pump();
      expect(tester.takeException(), isNull);
    } finally { semantics.dispose(); }
  });
}
