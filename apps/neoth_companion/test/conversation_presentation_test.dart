import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/conversation_models.dart';
import 'package:neoth_companion/conversation_presentation.dart';
import 'package:neoth_companion/companion_terminal_presentation.dart';
import 'package:neoth_companion/companion_theme.dart';
import 'package:neoth_companion/models.dart';

void main() {
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
