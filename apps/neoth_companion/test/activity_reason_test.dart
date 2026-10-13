import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/companion_activity_presentation.dart';
import 'package:neoth_companion/models.dart';

Map<String, Object?> _snapshot({String phase = 'failed', String? reason = 'peer_reported_error', bool incomplete = false}) => {
  'kind': 'chat_activity_snapshot_v2', 'activity_schema_version': 2,
  'request_id': '11111111-1111-1111-1111-111111111111', 'max_event_seq': 1,
  'incomplete': incomplete,
  'events': <Map<String, Object?>>[{'event_seq': 1, 'ordinal': 1, 'phase': phase, 'label': 'Tool call', if (reason != null) 'reason': reason}],
};

void main() {
  test('ACTIVITY-REASON-001 v1 stays strict and mixed observations decode', () {
    final v2 = _snapshot();
    expect(() => CompanionChatActivitySnapshot.fromBridgeJson(v2), throwsFormatException);
    final v1 = _snapshot(reason: null)..['kind'] = 'chat_activity_snapshot';
    v1['activity_schema_version'] = 1;
    expect(CompanionChatActivitySnapshot.fromBridgeObservation(v1).events.single.reason, isNull);
    final event = (v1['events']! as List<Map<String, Object?>>).single;
    event['reason'] = 'peer_reported_error';
    expect(() => CompanionChatActivitySnapshot.fromBridgeObservation(v1), throwsFormatException);
    expect(CompanionChatActivitySnapshot.fromBridgeObservation(v2).events.single.reason, CompanionToolActivityReason.peerReportedError);
  });

  test('ACTIVITY-REASON-002 causes require a failed phase and fixed reason', () {
    for (final phase in ['started', 'succeeded', 'rejected', 'unknown']) {
      expect(() => CompanionChatActivitySnapshot.fromBridgeObservation(_snapshot(phase: phase)), throwsFormatException);
    }
    expect(() => CompanionChatActivitySnapshot.fromBridgeObservation(_snapshot(reason: 'secret peer text')), throwsFormatException);
    final extra = _snapshot();
    (extra['events']! as List<Map<String, Object?>>).single['detail'] = '/private/path';
    expect(() => CompanionChatActivitySnapshot.fromBridgeObservation(extra), throwsFormatException);
  });

  test('ACTIVITY-REASON-003 v2 retains sequence count and label bounds', () {
    final stale = _snapshot()..['max_event_seq'] = 2;
    expect(() => CompanionChatActivitySnapshot.fromBridgeObservation(stale), throwsFormatException);
    final invalidLabel = _snapshot();
    (invalidLabel['events']! as List<Map<String, Object?>>).single['label'] = '/private/path';
    expect(() => CompanionChatActivitySnapshot.fromBridgeObservation(invalidLabel), throwsFormatException);
    final tooMany = _snapshot();
    tooMany['events'] = List<Map<String, Object?>>.generate(17, (i) => {'event_seq': i + 1, 'ordinal': i + 1, 'phase': 'failed', 'label': 'Tool call'});
    tooMany['max_event_seq'] = 17;
    expect(() => CompanionChatActivitySnapshot.fromBridgeObservation(tooMany), throwsFormatException);
  });

  testWidgets('ACTIVITY-REASON-004 card renders only the confirmed public reason', (tester) async {
    final snapshot = CompanionChatActivitySnapshot.fromBridgeObservation(_snapshot());
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: CompanionActivityCard(snapshot: snapshot))));
    expect(find.text('Failed'), findsOneWidget);
    expect(find.text('The tool reported an error.'), findsOneWidget);
    expect(find.text('Completed'), findsNothing);
    expect(find.byType(FilledButton), findsNothing);
  });

  testWidgets('ACTIVITY-REASON-005 unknown and incomplete do not invent a cause', (tester) async {
    final snapshot = CompanionChatActivitySnapshot.fromBridgeObservation(_snapshot(phase: 'unknown', reason: null, incomplete: true));
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: CompanionActivityCard(snapshot: snapshot))));
    expect(find.text('Outcome unknown'), findsOneWidget);
    expect(find.text('Some updates may be missing.'), findsOneWidget);
    expect(find.text('The tool reported an error.'), findsNothing);
  });
}
