import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/companion_controller.dart';
import 'package:neoth_companion/models.dart';
import 'package:neoth_companion/native_bridge.dart';
import 'package:neoth_companion/secure_store.dart';

void main() {
  activityModelRegressionCases();
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
  Uint8List secret = Uint8List.fromList(List<int>.filled(32, 9));

  @override
  Future<void> clearEnrollment() async => enrollment = null;
  @override
  Future<EnrollmentAccepted?> loadEnrollment() async => enrollment;
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
  _FakeBridge({this.pairResult, this.reconnectResult, this.chatResult, this.chatFuture});
  NativeBridgeResult? pairResult;
  NativeBridgeResult? reconnectResult;
  NativeBridgeResult? chatResult;
  Future<NativeBridgeResult>? chatFuture;
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
    return pairResult ?? const NativeBridgeResult(NativeOperationResult.failed);
  }
  @override
  Future<NativeBridgeResult> reconnect(String descriptorJson, String deviceId) async {
    reconnectCalls++;
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
