import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/companion_controller.dart';
import 'package:neoth_companion/models.dart';
import 'package:neoth_companion/native_bridge.dart';
import 'package:neoth_companion/secure_store.dart';
import 'package:neoth_companion/conversation_models.dart';

void main() {
  activityModelRegressionCases();
  streamRegressionCases();
  conversationRegressionCases();
  group('CompanionController', () {
    test('persists a public enrollment only after a real accepted bridge frame', () async {
      final store = _MemoryStore();
      final bridge = _FakeBridge(pairResult: _acceptedResult());
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.pair(_invite, 'Pixel');

      expect(store.enrollment?.deviceId, _deviceId);
      expect(store.enrollment?.reconnectDescriptor['carrier'], 'peeroxide-hyperswarm-v3');
      expect(controller.state, CompanionViewState.offline);
      expect(bridge.pairCalls, 1);
    });

    test('denied pairing never stores a descriptor or silently retries', () async {
      final store = _MemoryStore();
      final bridge = _FakeBridge(pairResult: _deniedResult('unknown_device'));
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.pair(_invite, 'Pixel');

      expect(store.enrollment, isNull);
      expect(controller.state, CompanionViewState.denied);
      expect(bridge.pairCalls, 1);
    });

    test('flat paired producer result persists its explicit chat scope and hex descriptor', () async {
      final store = _MemoryStore();
      final bridge = _FakeBridge(pairResult: _chatPairedResult());
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.pair(_chatInvite, 'Pixel');

      expect(store.enrollment?.grantedScope, 'companion.chat.send');
      expect(store.enrollment?.reconnectDescriptor['rendezvous_topic_hex'], hasLength(64));
      expect(controller.canSendChat, isTrue);
    });

    test('restored enrollment reaches the real status state only for its same device id', () async {
      final store = _MemoryStore(enrollment: _accepted());
      final bridge = _FakeBridge(reconnectResult: _statusResult());
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.refresh();

      expect(controller.state, CompanionViewState.ready);
      expect(controller.status?.deviceId, _deviceId);
      expect(bridge.reconnectCalls, 1);
    });

    test('unknown active-turn inventory remains unavailable instead of becoming empty', () async {
      final store = _MemoryStore(enrollment: _accepted());
      final bridge = _FakeBridge(reconnectResult: _statusWithUnavailableTurns());
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.refresh();

      expect(controller.state, CompanionViewState.ready);
      expect(controller.status?.activeTurns, isNull);
    });

    test('revocation stays visible and preserves the protected local identity until user action', () async {
      final store = _MemoryStore(enrollment: _accepted());
      final bridge = _FakeBridge(reconnectResult: _deniedResult('revoked'));
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.refresh();

      expect(controller.state, CompanionViewState.revoked);
      expect(store.enrollment?.deviceId, _deviceId);
      expect(bridge.reconnectCalls, 1);
    });

    test('lifecycle disposal asks the owned native bridge to cancel and drain', () async {
      final store = _MemoryStore();
      final bridge = _FakeBridge();
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      controller.dispose();
      await Future<void>.microtask(() {});

      expect(bridge.disposeCalls, 1);
    });

    test('chat activity binds the first request, preserves loss notification, and terminal clears it', () async {
      final pending = Completer<NativeBridgeResult>();
      final bridge = _FakeBridge(chatFuture: pending.future);
      final controller = CompanionController(store: _MemoryStore(enrollment: _chatAccepted()), bridgeFactory: (_) => bridge);
      await controller.prepareBridge(); await controller.restore();
      final send = controller.sendChat('ordinary text'); await Future<void>.microtask(() {});
      bridge.emitActivity(_activity(request: '11111111-1111-1111-1111-111111111111', maximum: 1, incomplete: false));
      bridge.emitActivity(_activity(request: '11111111-1111-1111-1111-111111111111', maximum: 1, incomplete: true));
      bridge.emitActivity(_activity(request: '11111111-1111-1111-1111-111111111111', maximum: 2, incomplete: false));
      bridge.emitActivity(_activity(request: '55555555-5555-5555-5555-555555555555', maximum: 2, incomplete: false));
      expect(controller.chatActivity?.incomplete, isTrue);
      pending.complete(_chatAcceptedResult()); await send;
      expect(controller.chatActivity, isNull);
    });

    test('forget invalidates an old completion and clears local pending state while native drains', () async {
      final pending = Completer<NativeBridgeResult>(); final bridge = _FakeBridge(chatFuture: pending.future);
      final controller = CompanionController(store: _MemoryStore(enrollment: _chatAccepted()), bridgeFactory: (_) => bridge);
      await controller.prepareBridge(); await controller.restore();
      final send = controller.sendChat('ordinary text'); await Future<void>.microtask(() {});
      await controller.forgetLocalEnrollment();
      expect(controller.chatPending, isFalse); expect(bridge.cancelActiveChatCalls, 1);
      pending.complete(_chatAcceptedResult()); await send;
      expect(controller.chatTerminal, isNull); expect(controller.chatLocalMessage, isNull);
    });

    test('chat-scope enrollment sends one accepted terminal and never retries it', () async {
      final store = _MemoryStore(enrollment: _chatAccepted());
      final bridge = _FakeBridge(chatResult: _chatAcceptedResult());
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.sendChat('ordinary text');

      expect(controller.chatTerminal?.outcome, 'accepted');
      expect(controller.chatTerminal?.records.single.text, 'hello');
      expect(bridge.chatCalls, 1);
    });

    test('status-only enrollment refuses chat locally without starting a bridge operation', () async {
      final store = _MemoryStore(enrollment: _accepted());
      final bridge = _FakeBridge();
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.sendChat('ordinary text');

      expect(bridge.chatCalls, 0);
      expect(controller.chatLocalMessage, contains('does not have chat permission'));
    });

    test('typed indeterminate terminal remains visible and is not retried', () async {
      final store = _MemoryStore(enrollment: _chatAccepted());
      final bridge = _FakeBridge(chatResult: _chatIndeterminateResult());
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.sendChat('ordinary text');

      expect(controller.chatTerminal?.outcome, 'indeterminate');
      expect(bridge.chatCalls, 1);
    });

    test('a public busy terminal stays typed even when the ABI uses its failed result code', () async {
      final store = _MemoryStore(enrollment: _chatAccepted());
      final bridge = _FakeBridge(chatResult: _chatBusyResult());
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      await controller.sendChat('ordinary text');

      expect(controller.chatTerminal?.outcome, 'busy');
      expect(bridge.chatCalls, 1);
    });

    test('stop waiting is gated to one pending chat and does not start another request', () async {
      final pending = Completer<NativeBridgeResult>();
      final store = _MemoryStore(enrollment: _chatAccepted());
      final bridge = _FakeBridge(chatFuture: pending.future);
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      final send = controller.sendChat('ordinary text');
      await Future<void>.microtask(() {});
      expect(controller.canStopWaiting, isTrue);
      await controller.cancelChat();
      await controller.cancelChat();
      expect(controller.chatCancelRequested, isTrue);
      expect(controller.canStopWaiting, isFalse);
      expect(bridge.cancelActiveChatCalls, 1);
      expect(bridge.chatCalls, 1);

      pending.complete(const NativeBridgeResult(NativeOperationResult.cancelled));
      await send;
      expect(controller.chatPending, isFalse);
      expect(controller.chatLocalMessage, 'Waiting stopped before a terminal was confirmed.');
      await controller.cancelChat();
      expect(bridge.cancelActiveChatCalls, 1);
    });

    test('a terminal accepted while stopping wait remains accepted and is not relabelled', () async {
      final pending = Completer<NativeBridgeResult>();
      final store = _MemoryStore(enrollment: _chatAccepted());
      final bridge = _FakeBridge(chatFuture: pending.future);
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      final send = controller.sendChat('ordinary text');
      await Future<void>.microtask(() {});
      await controller.cancelChat();
      pending.complete(_chatAcceptedResult());
      await send;

      expect(bridge.cancelActiveChatCalls, 1);
      expect(controller.chatTerminal?.outcome, 'accepted');
      expect(controller.chatLocalMessage, isNull);
    });

    test('a terminal that wins before the scheduled native cancel is not signalled late', () async {
      final pending = Completer<NativeBridgeResult>();
      final store = _MemoryStore(enrollment: _chatAccepted());
      final bridge = _FakeBridge(chatFuture: pending.future);
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      final send = controller.sendChat('ordinary text');
      await Future<void>.microtask(() {});
      final stopping = controller.cancelChat();
      pending.complete(_chatAcceptedResult());
      await stopping;
      await send;

      expect(bridge.cancelActiveChatCalls, 0);
      expect(controller.chatTerminal?.outcome, 'accepted');
    });

    test('post-write indeterminate terminal remains typed after stopping wait', () async {
      final pending = Completer<NativeBridgeResult>();
      final store = _MemoryStore(enrollment: _chatAccepted());
      final bridge = _FakeBridge(chatFuture: pending.future);
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      final send = controller.sendChat('ordinary text');
      await Future<void>.microtask(() {});
      await controller.cancelChat();
      pending.complete(_chatIndeterminateResult());
      await send;

      expect(controller.chatTerminal?.outcome, 'indeterminate');
      expect(controller.chatLocalMessage, isNull);
      expect(bridge.cancelActiveChatCalls, 1);
    });

    test('dispose delegates cancellation and drain to the native bridge while chat is pending', () async {
      final pending = Completer<NativeBridgeResult>();
      final store = _MemoryStore(enrollment: _chatAccepted());
      final bridge = _FakeBridge(chatFuture: pending.future);
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);

      await controller.prepareBridge();
      await controller.restore();
      unawaited(controller.sendChat('ordinary text'));
      await Future<void>.microtask(() {});
      controller.dispose();
      await Future<void>.microtask(() {});

      expect(bridge.disposeCalls, 1);
      expect(bridge.cancelActiveChatCalls, 0);
    });
  });
}

const _deviceId = '7fb8ae0f-9e36-4a64-83e2-972dff9af880';
const _invite = 'neoth://companion/pair?v=3&topic=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&psk=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&server_pk=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc&ttl=60&scope=companion.status.read';
const _chatInvite = 'neoth://companion/pair?v=3&topic=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&psk=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&server_pk=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc&ttl=60&scope=companion.chat.send';

EnrollmentAccepted _accepted() => const EnrollmentAccepted(
      deviceId: _deviceId,
      revision: 1,
      grantedScope: 'companion.status.read',
      reconnectDescriptor: <String, Object?>{
        'schema_version': 3,
        'carrier': 'peeroxide-hyperswarm-v3',
        'rendezvous_topic_hex': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'daemon_noise_public_key_hex': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'descriptor_generation': 1,
      },
    );

NativeBridgeResult _acceptedResult() => NativeBridgeResult(NativeOperationResult.ok, <String, Object?>{
      'state': 'paired',
      'device_id': _deviceId,
      'revision': 1,
      'granted_scope': 'companion.status.read',
      'descriptor': _accepted().reconnectDescriptor,
    });

NativeBridgeResult _chatPairedResult() => NativeBridgeResult(NativeOperationResult.ok, <String, Object?>{
      'state': 'paired',
      'device_id': _deviceId,
      'revision': 2,
      'granted_scope': 'companion.chat.send',
      'descriptor': _accepted().reconnectDescriptor,
    });

NativeBridgeResult _statusResult() => const NativeBridgeResult(NativeOperationResult.ok, <String, Object?>{
      'state': 'status',
      'device_id': _deviceId,
      'daemon_boot_id': 'boot-a',
      'readiness': 'ready',
      'observed_at_unix': 1700000000,
      'active_turns': <Object?>[],
    });

NativeBridgeResult _statusWithUnavailableTurns() => const NativeBridgeResult(NativeOperationResult.ok, <String, Object?>{
      'state': 'status',
      'device_id': _deviceId,
      'daemon_boot_id': 'boot-a',
      'readiness': 'ready',
      'observed_at_unix': 1700000000,
      'active_turns': null,
    });

NativeBridgeResult _deniedResult(String code) => NativeBridgeResult(NativeOperationResult.denied, <String, Object?>{
      'state': 'denied',
      'code': code,
    });

EnrollmentAccepted _chatAccepted() => EnrollmentAccepted(
      deviceId: _deviceId,
      revision: 2,
      grantedScope: 'companion.chat.send',
      reconnectDescriptor: _accepted().reconnectDescriptor,
    );

NativeBridgeResult _chatAcceptedResult() => const NativeBridgeResult(NativeOperationResult.ok, <String, Object?>{
      'kind': 'chat',
      'schema_version': 3,
      'request_id': '11111111-1111-1111-1111-111111111111',
      'outcome': 'accepted',
      'records': <Object?>[
        <String, Object?>{'kind': 'stdout', 'text': 'hello'},
      ],
      'provider': 'provider-a',
      'model': 'model-a',
    });

NativeBridgeResult _chatIndeterminateResult() => const NativeBridgeResult(NativeOperationResult.ok, <String, Object?>{
      'kind': 'chat',
      'schema_version': 3,
      'request_id': '22222222-2222-2222-2222-222222222222',
      'outcome': 'indeterminate',
      'records': <Object?>[],
    });

NativeBridgeResult _chatBusyResult() => const NativeBridgeResult(NativeOperationResult.failed, <String, Object?>{
      'kind': 'chat',
      'schema_version': 3,
      'request_id': '33333333-3333-3333-3333-333333333333',
      'outcome': 'busy',
      'records': <Object?>[],
    });

class _MemoryStore implements CompanionStore {
  _MemoryStore({this.enrollment});
  EnrollmentAccepted? enrollment;
  Future<EnrollmentAccepted?>? loadFuture;
  Uint8List secret = Uint8List.fromList(List<int>.filled(32, 9));

  @override
  Future<void> clearEnrollment() async => enrollment = null;
  @override
  Future<EnrollmentAccepted?> loadEnrollment() async {
    if (loadFuture != null) return loadFuture!;
    return enrollment;
  }
  @override
  Future<Uint8List> loadOrCreateDeviceSecret() async => Uint8List.fromList(secret);
  @override
  Future<void> saveEnrollment(EnrollmentAccepted value) async => enrollment = value;
}

CompanionChatActivitySnapshot _activity({required String request, required int maximum, required bool incomplete}) => CompanionChatActivitySnapshot(
  requestId: request, maxEventSeq: maximum, incomplete: incomplete,
  events: [CompanionToolActivityEvent(eventSeq: maximum, ordinal: 1, phase: CompanionToolActivityPhase.started, label: 'Read file')],
);

class _FakeBridge implements NativeBridgeWithActivity {
  _FakeBridge({this.pairResult, this.reconnectResult, this.chatResult, this.chatFuture, this.pairFuture, this.reconnectFuture});
  NativeBridgeResult? pairResult;
  NativeBridgeResult? reconnectResult;
  NativeBridgeResult? chatResult;
  Future<NativeBridgeResult>? chatFuture;
  Future<NativeBridgeResult>? pairFuture;
  Future<NativeBridgeResult>? reconnectFuture;
  int pairCalls = 0;
  int reconnectCalls = 0;
  int chatCalls = 0;
  int disposeCalls = 0;
  int cancelActiveChatCalls = 0;
  void Function(CompanionChatActivitySnapshot)? _activity;
  void emitActivity(CompanionChatActivitySnapshot value) => _activity?.call(value);

  @override
  Future<void> dispose() async => disposeCalls++;
  @override
  Future<NativeBridgeResult> pair(String inviteUrl, String label) async {
    pairCalls++;
    if (pairFuture != null) return pairFuture!;
    return pairResult ?? const NativeBridgeResult(NativeOperationResult.failed);
  }
  @override
  Future<NativeBridgeResult> reconnect(String descriptorJson, String deviceId) async {
    reconnectCalls++;
    if (reconnectFuture != null) return reconnectFuture!;
    return reconnectResult ?? const NativeBridgeResult(NativeOperationResult.failed);
  }
  @override
  Future<NativeBridgeResult> chat(String descriptorJson, String deviceId, String message) async {
    chatCalls++;
    if (chatFuture != null) return chatFuture!;
    return chatResult ?? const NativeBridgeResult(NativeOperationResult.failed);
  }
  @override
  Future<NativeBridgeResult> chatWithActivity(String descriptorJson, String deviceId, String message, void Function(CompanionChatActivitySnapshot) onActivity) {
    _activity = onActivity;
    return chat(descriptorJson, deviceId, message);
  }
  @override
  Future<void> cancelActiveChat() async => cancelActiveChatCalls++;
}

void activityModelRegressionCases() {
  test('activity model rejects an unknown phase, unallowlisted label, and extra schema key', () {
    final valid = <String, Object?>{
      'kind': 'chat_activity_snapshot', 'activity_schema_version': 1,
      'request_id': _deviceId, 'max_event_seq': 1, 'incomplete': false,
      'events': <Object?>[<String, Object?>{'event_seq': 1, 'ordinal': 1, 'phase': 'started', 'label': 'Read file'}],
    };
    expect(CompanionChatActivitySnapshot.fromBridgeJson(valid).events.single.label, 'Read file');
    expect(() => CompanionChatActivitySnapshot.fromBridgeJson(<String, Object?>{...valid, 'unexpected': true}), throwsFormatException);
    expect(() => CompanionToolActivityEvent.fromJson(<String, Object?>{'event_seq': 1, 'ordinal': 1, 'phase': 'other', 'label': 'Read file'}, 0), throwsFormatException);
    expect(() => CompanionToolActivityEvent.fromJson(<String, Object?>{'event_seq': 1, 'ordinal': 1, 'phase': 'started', 'label': 'sensitive path'}, 0), throwsFormatException);
  });
}

class _StreamBridge extends _FakeBridge implements NativeBridgeWithStream {
  _StreamBridge(Future<NativeBridgeResult> result) : super(chatFuture: result);
  void Function(CompanionChatStreamSnapshot)? observer;
  @override
  Future<NativeBridgeResult> chatWithStream(String descriptorJson, String deviceId, String message,
      void Function(CompanionChatActivitySnapshot) onActivity, void Function(CompanionChatStreamSnapshot) onStream) {
    observer = onStream;
    return chatWithActivity(descriptorJson, deviceId, message, onActivity);
  }
}

void streamRegressionCases() {
  test('stream model bounds UTF8 and rejects invalid revisions and extra keys', () {
    final valid = <String, Object?>{'kind': 'chat_stream_snapshot', 'stream_schema_version': 1,
      'request_id': _deviceId, 'revision': 1, 'text': 'hello', 'truncated': false};
    expect(CompanionChatStreamSnapshot.fromBridgeJson(valid).text, 'hello');
    expect(() => CompanionChatStreamSnapshot.fromBridgeJson({...valid, 'revision': 0}), throwsFormatException);
    expect(() => CompanionChatStreamSnapshot.fromBridgeJson({...valid, 'text': List.filled(4000, '€').join()}), throwsFormatException);
    expect(() => CompanionChatStreamSnapshot.fromBridgeJson({...valid, 'secret': true}), throwsFormatException);
  });
  test('live preview replaces skipped revisions and terminal removes it once', () async {
    final done = Completer<NativeBridgeResult>();
    final bridge = _StreamBridge(done.future);
    final controller = CompanionController(store: _MemoryStore(enrollment: _chatAccepted()), bridgeFactory: (_) => bridge);
    await controller.prepareBridge(); await controller.restore();
    final running = controller.sendChat('hello');
    void preview(int revision, String text, [String request = '11111111-1111-1111-1111-111111111111']) =>
        bridge.observer!(CompanionChatStreamSnapshot(requestId: request, revision: revision, text: text, truncated: false));
    preview(1, 'hel'); preview(3, 'hello');
    preview(2, 'stale'); preview(9, 'foreign', _deviceId);
    expect(controller.chatPreview?.text, 'hello');
    expect(controller.chatPending, isTrue);
    done.complete(_chatAcceptedResult()); await running;
    expect(controller.chatPreview, isNull);
    expect(controller.chatTerminal?.records.single.text, 'hello');
    preview(4, 'too late');
    expect(controller.chatPreview, isNull);
    expect(bridge.chatCalls, 1);
    controller.dispose();
  });
  test('forget clears live content before waiting and fences old stream callbacks', () async {
    final done = Completer<NativeBridgeResult>();
    final bridge = _StreamBridge(done.future);
    final controller = CompanionController(store: _MemoryStore(enrollment: _chatAccepted()), bridgeFactory: (_) => bridge);
    await controller.prepareBridge(); await controller.restore();
    final running = controller.sendChat('hello');
    final callback = bridge.observer!;
    const preview = CompanionChatStreamSnapshot(requestId: '11111111-1111-1111-1111-111111111111',
      revision: 1, text: 'private preview', truncated: false);
    callback(preview);
    expect(controller.chatPreview, isNotNull);
    final clearing = controller.forgetLocalEnrollment();
    expect(controller.chatPreview, isNull);
    callback(preview);
    done.complete(_chatAcceptedResult()); await running; await clearing;
    expect(controller.chatPreview, isNull);
    expect(controller.chatTerminal, isNull);
    expect(bridge.chatCalls, 1);
    controller.dispose();
  });
}

const _conversationId = '00000000-0000-4000-8000-000000000010';

class _ConversationStore extends _MemoryStore implements CompanionConversationStore {
  _ConversationStore() : super(enrollment: _chatAccepted());
  ConversationCheckpoint? checkpoint;
  bool failSave = false;
  Future<void>? clearGate;
  @override
  Future<ConversationCheckpoint?> loadConversationCheckpoint(EnrollmentAccepted enrollment) async =>
      checkpoint?.deviceId == enrollment.deviceId && checkpoint?.revision == enrollment.revision ? checkpoint : null;
  @override
  Future<void> saveConversationCheckpoint(ConversationCheckpoint value) async {
    if (failSave) throw StateError('save failure');
    checkpoint = ConversationCheckpoint.fromJson(jsonDecode(jsonEncode(value.toJson())) as Map<String, Object?>);
  }
  @override
  Future<void> clearEnrollment() async {
    if (clearGate != null) await clearGate;
    await super.clearEnrollment(); checkpoint = null;
  }
}

class _ConversationBridge extends _FakeBridge implements NativeBridgeWithConversation {
  final commands = <Map<String, Object?>>[];
  Future<NativeBridgeResult> Function(Map<String, Object?>)? handler;
  @override
  bool get conversationSupported => true;
  @override
  Future<NativeBridgeResult> conversation(String descriptorJson, String deviceId, String commandJson,
      void Function(CompanionChatActivitySnapshot) onActivity, void Function(CompanionChatStreamSnapshot) onStream) async {
    final command = jsonDecode(commandJson) as Map<String, Object?>;
    commands.add(command);
    return handler!(command);
  }
  @override
  Future<NativeBridgeResult> chatWithStream(String descriptorJson, String deviceId, String message,
      void Function(CompanionChatActivitySnapshot) onActivity, void Function(CompanionChatStreamSnapshot) onStream) =>
      throw StateError('conversation must not downgrade or resend');
}

Map<String, Object?> _conversationHistory(String requestId, {bool incognito = false, bool committed = true}) => {
  'conversation_schema_version': 1, 'request_id': requestId, 'revision': 2,
  'conversation_id': incognito ? null : _conversationId, 'state': incognito ? 'incognito' : 'available',
  'current_turn_committed': committed && !incognito, 'bounded_tail': true,
  'turns': incognito ? <Object?>[] : <Object?>[
    {'role': 'operator', 'text': 'ordinary message', 'truncated': false},
    {'role': 'agent', 'text': 'visible reply', 'truncated': false},
  ],
};

NativeBridgeResult _conversationTerminal(Map<String, Object?> command, {bool incognito = false}) => NativeBridgeResult(NativeOperationResult.ok, {
  'kind': 'chat', 'schema_version': 3, 'request_id': command['request_id'], 'outcome': 'accepted',
  'records': <Object?>[{'kind': 'stdout', 'text': 'visible reply'}], 'provider': 'provider-a', 'model': 'model-a',
  'conversation_admission': {'conversation_schema_version': 1, 'request_id': command['request_id'], 'revision': 2,
    'conversation_id': incognito ? null : _conversationId, 'incognito': incognito},
  'conversation_history': _conversationHistory(command['request_id']! as String, incognito: incognito),
});

Future<CompanionController> _conversationController(_ConversationStore store, _ConversationBridge bridge) async {
  final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);
  await controller.prepareBridge(); await controller.restore(); return controller;
}

void conversationRegressionCases() {
  test('JM05 forget fences late enrollment restore pairing and status completions', () async {
    for (final operation in ['restore', 'pair', 'refresh']) {
      final store = _MemoryStore(enrollment: operation == 'pair' ? null : _accepted());
      final loaded = Completer<EnrollmentAccepted?>();
      final result = Completer<NativeBridgeResult>();
      final bridge = _FakeBridge(
        pairFuture: operation == 'pair' ? result.future : null,
        reconnectFuture: operation == 'refresh' ? result.future : null);
      final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);
      await controller.prepareBridge();
      if (operation == 'refresh') await controller.restore();
      if (operation == 'restore') store.loadFuture = loaded.future;
      final pending = operation == 'restore' ? controller.restore()
          : operation == 'pair' ? controller.pair(_invite, 'Pixel') : controller.refresh();
      await controller.forgetLocalEnrollment();
      if (operation == 'restore') {
        loaded.complete(_accepted());
      } else {
        result.complete(operation == 'pair' ? _acceptedResult() : _statusResult());
      }
      await pending;
      expect(controller.state, CompanionViewState.unpaired, reason: operation);
      expect(controller.grantedScope, isNull, reason: operation);
      expect(controller.status, isNull, reason: operation);
      expect(store.enrollment, isNull, reason: operation);
      expect(bridge.chatCalls, 0, reason: operation);
      controller.dispose();
    }
  });

  test('JM05 restored conversation never downgrades to a legacy one-off send', () async {
    final store = _ConversationStore();
    store.checkpoint = ConversationCheckpoint(deviceId: _deviceId, revision: 2,
      conversationIds: [_conversationId], selectedId: _conversationId);
    final bridge = _FakeBridge();
    final controller = CompanionController(store: store, bridgeFactory: (_) => bridge);
    await controller.prepareBridge(); await controller.restore();
    await controller.sendChat('must retain this conversation');
    expect(bridge.chatCalls, 0);
    expect(controller.selectedConversationId, _conversationId);
    expect(controller.chatLocalMessage, contains('support is unavailable'));
    expect(store.checkpoint?.pendingRequestId, isNull);
    controller.dispose();
  });

  test('JM05 forget blocks new sends before protected storage has finished clearing', () async {
    final gate = Completer<void>();
    final store = _ConversationStore()..clearGate = gate.future;
    final bridge = _ConversationBridge();
    final controller = await _conversationController(store, bridge);
    final clearing = controller.forgetLocalEnrollment();
    expect(controller.canSendChat, isFalse);
    await controller.sendChat('must not start during forget');
    await controller.pair(_invite, 'must not pair during forget');
    expect(bridge.commands, isEmpty); expect(bridge.chatCalls, 0); expect(bridge.pairCalls, 0);
    gate.complete(); await clearing;
    expect(controller.state, CompanionViewState.unpaired);
    expect(store.enrollment, isNull); expect(store.checkpoint, isNull);
    controller.dispose();
  });

  test('JM05 conversation persists public intent before send and resumes one canonical history', () async {
    final store = _ConversationStore(); final bridge = _ConversationBridge();
    bridge.handler = (command) async {
      expect(store.checkpoint?.pendingRequestId, command['request_id']);
      expect(jsonEncode(store.checkpoint!.toJson()), isNot(contains('ordinary message')));
      return _conversationTerminal(command);
    };
    final controller = await _conversationController(store, bridge);
    await controller.sendChat('ordinary message');
    expect(controller.terminalCoveredByHistory, isTrue);
    expect(controller.selectedConversationId, _conversationId);
    expect(controller.conversationPendingMessage, isNull);
    expect(store.checkpoint?.pendingRequestId, isNull);
    await controller.sendChat('ordinary follow-up');
    expect(bridge.commands, hasLength(2));
    final action = bridge.commands.last['action']! as Map;
    expect(action['operation'], 'resume'); expect(action['conversation_id'], _conversationId);
    expect(bridge.commands.first['request_id'], isNot(bridge.commands.last['request_id']));
    expect(bridge.chatCalls, 0);
    controller.dispose();
  });

  test('JM05 restart recovers lost admission with a read command and never repeats the prompt', () async {
    final store = _ConversationStore(); final bridge = _ConversationBridge();
    const pending = '00000000-0000-4000-8000-000000000011';
    store.checkpoint = ConversationCheckpoint(deviceId: _deviceId, revision: 2, pendingRequestId: pending);
    bridge.handler = (command) async => NativeBridgeResult(NativeOperationResult.ok,
      {'kind': 'conversation_history', ..._conversationHistory(command['request_id']! as String, committed: false)});
    final controller = await _conversationController(store, bridge);
    await controller.sendChat('must not be sent'); expect(bridge.commands, isEmpty);
    await controller.recoverConversation();
    expect(bridge.commands, hasLength(1));
    final action = bridge.commands.single['action']! as Map;
    expect(action, {'operation': 'recover', 'created_by_request': pending});
    expect(controller.selectedConversationId, _conversationId);
    expect(controller.conversationNeedsRecovery, isFalse);
    expect(controller.chatTerminal, isNull);
    expect(controller.chatLocalMessage, contains('unconfirmed'));
    controller.dispose();
  });

  test('JM05 store failure prevents start and foreign revision preserves unresolved intent', () async {
    final store = _ConversationStore()..failSave = true; final bridge = _ConversationBridge();
    final controller = await _conversationController(store, bridge);
    await controller.sendChat('not started'); expect(bridge.commands, isEmpty);
    store.failSave = false;
    bridge.handler = (command) async {
      final value = _conversationTerminal(command);
      final json = <String, Object?>{...value.publicJson!};
      json['conversation_admission'] = {...(json['conversation_admission']! as Map<String, Object?>), 'revision': 99};
      return NativeBridgeResult(NativeOperationResult.ok, json);
    };
    await controller.sendChat('ordinary message');
    expect(controller.chatTerminal, isNull); expect(controller.selectedConversationId, isNull);
    expect(controller.conversationNeedsRecovery, isTrue); expect(bridge.commands, hasLength(1));
    controller.dispose();
  });

  test('JM05 forget wins a late conversation completion and clears the public checkpoint', () async {
    final store = _ConversationStore(); final bridge = _ConversationBridge();
    final entered = Completer<Map<String, Object?>>(); final reply = Completer<NativeBridgeResult>();
    bridge.handler = (command) { entered.complete(command); return reply.future; };
    final controller = await _conversationController(store, bridge);
    final sending = controller.sendChat('ordinary message');
    final command = await entered.future;
    await controller.forgetLocalEnrollment(); reply.complete(_conversationTerminal(command)); await sending;
    expect(store.checkpoint, isNull); expect(controller.conversationIds, isEmpty);
    expect(controller.conversationHistory, isNull); expect(controller.chatTerminal, isNull);
    expect(bridge.commands, hasLength(1)); controller.dispose();
  });

  test('JM05 incognito stays outside saved history and unavailable rows do not hide the terminal', () async {
    final store = _ConversationStore(); final bridge = _ConversationBridge();
    bridge.handler = (command) async => _conversationTerminal(command, incognito: true);
    final controller = await _conversationController(store, bridge);
    controller.setConversationIncognito(true); await controller.sendChat('private message');
    expect((bridge.commands.single['action']! as Map)['incognito'], isTrue);
    expect(controller.conversationIds, isEmpty); expect(controller.conversationHistory?.turns, isEmpty);
    expect(controller.terminalCoveredByHistory, isFalse);
    expect(jsonEncode(store.checkpoint!.toJson()), isNot(contains('private message')));
    final rowless = _conversationHistory(controller.chatTerminal!.requestId);
    rowless['turns'] = <Object?>[{'role': 'agent', 'text': null, 'truncated': true}];
    controller.conversationHistory = ConversationHistory.fromJson(rowless);
    expect(controller.terminalCoveredByHistory, isFalse); controller.dispose();
  });

  test('JM05 public history rejects private fields oversized escaped rows and missing text lies', () {
    final value = _conversationHistory('00000000-0000-4000-8000-000000000011');
    expect(() => ConversationHistory.fromJson({...value, 'private_session_id': 'forbidden'}), throwsFormatException);
    expect(() => ConversationHistory.fromJson({...value, 'turns': [{'role': 'agent', 'text': null, 'truncated': false}]}), throwsFormatException);
    expect(() => ConversationHistory.fromJson({...value, 'turns': [{'role': 'operator', 'text': List.filled(16384, '\u0001').join(), 'truncated': false}]}), throwsFormatException);
    expect(() => ConversationHistory.fromJson({...value, 'state': 'unavailable'}), throwsFormatException);
  });
}
