import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'bridge_input.dart';
import 'models.dart';
import 'native_bridge.dart';
import 'secure_store.dart';
import 'conversation_models.dart';

typedef NativeBridgeFactory = NativeBridge Function(Uint8List secret);

/// Keeps pairing authority explicit: success is persisted exactly once, while
/// denied/revoked responses retain the old identity and never trigger re-pair.
class CompanionController extends ChangeNotifier {
  CompanionController({required CompanionStore store, required NativeBridgeFactory bridgeFactory})
      : _store = store,
        _bridgeFactory = bridgeFactory;

  final CompanionStore _store;
  final NativeBridgeFactory _bridgeFactory;
  NativeBridge? _bridge;
  EnrollmentAccepted? _enrollment;
  CompanionStatus? status;
  CompanionChatTerminal? chatTerminal;
  CompanionChatActivitySnapshot? chatActivity;
  CompanionChatStreamSnapshot? chatPreview;
  String? chatLocalMessage;
  bool chatPending = false;
  bool chatCancelRequested = false;
  CompanionViewState state = CompanionViewState.unpaired;
  bool _disposed = false;
  bool _forgetting = false;
  int _authorityEpoch = 0;
  bool _ownsAuthority(int epoch) => !_disposed && !_forgetting && epoch == _authorityEpoch;
  int _chatEpoch = 0;
  String? _chatRequestId;
  int _activityMaximum = -1;
  bool _activityIncomplete = false;
  ConversationCheckpoint? _conversation;
  ConversationHistory? conversationHistory;
  bool conversationIncognito = false;
  String? conversationPendingMessage;

  bool get conversationsAvailable => canSendChat && _store is CompanionConversationStore
      && _bridge is NativeBridgeWithConversation && (_bridge! as NativeBridgeWithConversation).conversationSupported;
  bool get conversationNeedsRecovery => _conversation?.pendingRequestId != null;
  List<String> get conversationIds => _conversation?.conversationIds ?? const [];
  String? get selectedConversationId => _conversation?.selectedId;
  bool get terminalCoveredByHistory {
    final terminal = chatTerminal; final history = conversationHistory;
    if (terminal == null || history == null || !terminal.accepted || !history.currentTurnCommitted || history.requestId != terminal.requestId
        || history.turns.isEmpty || terminal.records.length != 1) return false;
    // Commitment comes from the request-bound receipt above. Exact visible
    // equality is only a presentation check: a truncated/sanitized history
    // row must never hide a different or more complete terminal answer.
    final last = history.turns.last; final record = terminal.records.single;
    return last.role == 'agent' && !last.truncated && record.kind == 'stdout' && last.text == record.text;
  }

  Future<void> _restoreConversation(EnrollmentAccepted enrollment) async {
    final epoch = _authorityEpoch;
    if (_store case final CompanionConversationStore store) {
      final value = await store.loadConversationCheckpoint(enrollment);
      if (_ownsAuthority(epoch) && _enrollment?.deviceId == enrollment.deviceId && _enrollment?.revision == enrollment.revision) {
        _conversation = value ?? ConversationCheckpoint(deviceId: enrollment.deviceId, revision: enrollment.revision);
        if (conversationNeedsRecovery) chatLocalMessage = 'A previous send has an unconfirmed outcome. Recover saved history before continuing.';
      }
    }
  }

  Future<void> restore() async {
    if (_disposed || _forgetting) return;
    final epoch = _authorityEpoch;
    final enrollment = await _store.loadEnrollment();
    if (!_ownsAuthority(epoch)) return;
    _enrollment = enrollment;
    if (_enrollment == null) {
      _set(CompanionViewState.unpaired);
      return;
    }
    await _restoreConversation(_enrollment!);
    if (_ownsAuthority(epoch)) _set(CompanionViewState.offline);
  }

  Future<void> pair(String rawInvite, String label) async {
    if (_disposed || _forgetting || state == CompanionViewState.pairing) return;
    // A retained active enrollment must be deliberately cleared by the person
    // holding the device; a pasted invite cannot silently replace it.
    if (_enrollment != null) {
      _set(CompanionViewState.failed);
      return;
    }
    final epoch = _authorityEpoch;
    _set(CompanionViewState.pairing);
    try {
      final result = await _ensureBridge().pair(rawInvite.trim(), label.trim());
      if (!_ownsAuthority(epoch)) return;
      if (result.kind == NativeOperationResult.ok && result.publicJson != null) {
        final accepted = EnrollmentAccepted.fromBridgeJson(result.publicJson!);
        await _store.saveEnrollment(accepted); // durable only after actual success
        if (!_ownsAuthority(epoch)) return;
        _enrollment = accepted;
        await _restoreConversation(accepted);
        if (_ownsAuthority(epoch)) _set(CompanionViewState.offline);
      } else {
        _setForResult(result);
      }
    } on FormatException {
      if (_ownsAuthority(epoch)) _set(CompanionViewState.failed);
    } on StateError {
      if (_ownsAuthority(epoch)) _set(CompanionViewState.failed);
    }
  }

  Future<void> refresh() async {
    if (_disposed || _forgetting || state == CompanionViewState.pairing) return;
    final enrollment = _enrollment;
    if (enrollment == null) {
      _set(CompanionViewState.unpaired);
      return;
    }
    final epoch = _authorityEpoch;
    _set(CompanionViewState.pairing);
    try {
      final result = await _ensureBridge().reconnect(jsonEncode(enrollment.reconnectDescriptor), enrollment.deviceId);
      if (!_ownsAuthority(epoch)) return;
      if (result.kind == NativeOperationResult.ok && result.publicJson != null) {
        final snapshot = CompanionStatus.fromBridgeJson(result.publicJson!);
        if (snapshot.deviceId != enrollment.deviceId) throw const FormatException('cross-device status');
        status = snapshot;
        _set(CompanionViewState.ready);
      } else {
        _setForResult(result);
      }
    } on FormatException {
      if (_ownsAuthority(epoch)) _set(CompanionViewState.failed);
    } on StateError {
      if (_ownsAuthority(epoch)) _set(CompanionViewState.offline);
    }
  }

  bool get canSendChat => _enrollment?.grantedScope == companionChatSendScope;
  bool get canRefreshStatus => _enrollment?.grantedScope == companionStatusReadScope;
  bool get canStopWaiting => chatPending && !chatCancelRequested;
  String? get grantedScope => _enrollment?.grantedScope;

  /// Starts exactly one ordinary text turn. A local validation error is known
  /// before the bridge worker starts; every remote terminal is rendered from
  /// its typed public outcome and is never retried here.
  Future<void> sendChat(String message) async {
    if (_disposed || _forgetting || chatPending) return;
    final enrollment = _enrollment;
    if (enrollment == null || !canSendChat) {
      chatLocalMessage = 'This phone does not have chat permission. Pair again with a chat invite.';
      _notify();
      return;
    }
    try {
      validateOrdinaryChatMessage(message);
    } on FormatException {
      chatLocalMessage = 'Enter one ordinary message of at most 640 UTF-8 bytes. Slash actions are unavailable.';
      _notify();
      return;
    }
    if (!conversationsAvailable && (selectedConversationId != null || conversationNeedsRecovery)) {
      chatLocalMessage = 'Saved conversation support is unavailable on this installation. No message was sent.';
      _notify();
      return;
    }
    if (conversationsAvailable) {
      await _sendConversation(enrollment, message);
      return;
    }
    final epoch = ++_chatEpoch;
    chatPending = true;
    chatCancelRequested = false;
    chatTerminal = null;
    chatActivity = null;
    chatPreview = null;
    _chatRequestId = null;
    _activityMaximum = -1;
    _activityIncomplete = false;
    chatLocalMessage = null;
    _notify();
    try {
      final bridge = _ensureBridge();
      final result = bridge is NativeBridgeWithStream
          ? await bridge.chatWithStream(jsonEncode(enrollment.reconnectDescriptor), enrollment.deviceId, message,
              (snapshot) => _acceptActivity(epoch, snapshot), (snapshot) => _acceptStream(epoch, snapshot))
          : bridge is NativeBridgeWithActivity
          ? await bridge.chatWithActivity(jsonEncode(enrollment.reconnectDescriptor), enrollment.deviceId, message, (snapshot) => _acceptActivity(epoch, snapshot))
          : await bridge.chat(jsonEncode(enrollment.reconnectDescriptor), enrollment.deviceId, message);
      if (epoch != _chatEpoch) return;
      if (result.publicJson != null) {
        // A confirmed public terminal wins any earlier local stop presentation.
        // In particular, an accepted response must not retain "Stop requested".
        chatLocalMessage = null;
        final terminal = CompanionChatTerminal.fromBridgeJson(result.publicJson!);
        if (epoch != _chatEpoch || (_chatRequestId != null && _chatRequestId != terminal.requestId)) throw const FormatException('cross-request terminal');
        chatActivity = null;
        chatPreview = null;
        chatTerminal = terminal;
      } else if (result.kind == NativeOperationResult.cancelled) {
        chatLocalMessage = 'Waiting stopped before a terminal was confirmed.';
      } else {
        chatLocalMessage = 'Chat could not be started. No message is retried automatically.';
      }
    } on FormatException {
      if (epoch == _chatEpoch) chatLocalMessage = 'The chat response could not be verified.';
    } on StateError {
      if (epoch == _chatEpoch) chatLocalMessage = 'NEOTH is unavailable. No message is retried automatically.';
    } finally {
      if (epoch == _chatEpoch) { chatPreview = null; chatPending = false; chatCancelRequested = false; _notify(); }
    }
  }

  void _acceptActivity(int epoch, CompanionChatActivitySnapshot snapshot) {
    if (_disposed || epoch != _chatEpoch || !chatPending || chatTerminal != null) return;
    if (_chatRequestId == null) { _chatRequestId = snapshot.requestId; } else if (_chatRequestId != snapshot.requestId) { return; }
    if (snapshot.maxEventSeq < _activityMaximum) return;
    if (snapshot.maxEventSeq == _activityMaximum && !(chatActivity?.incomplete == false && snapshot.incomplete)) return;
    _activityIncomplete = _activityIncomplete || snapshot.incomplete;
    _activityMaximum = snapshot.maxEventSeq;
    chatActivity = _activityIncomplete == snapshot.incomplete
        ? snapshot
        : CompanionChatActivitySnapshot(requestId: snapshot.requestId, maxEventSeq: snapshot.maxEventSeq, incomplete: true, events: snapshot.events);
    _notify();
  }

  Future<void> selectConversation(String? conversationId) async {
    if (_disposed || _forgetting || chatPending || conversationNeedsRecovery || !conversationsAvailable) return;
    final enrollment = _enrollment!;
    final current = _conversation ?? ConversationCheckpoint(deviceId: enrollment.deviceId, revision: enrollment.revision);
    final next = ConversationCheckpoint(deviceId: enrollment.deviceId, revision: enrollment.revision,
      conversationIds: current.conversationIds, selectedId: conversationId);
    final epoch = ++_chatEpoch;
    chatPending = true; _notify();
    try {
      await (_store as CompanionConversationStore).saveConversationCheckpoint(next);
      if (_disposed || epoch != _chatEpoch) return;
      _conversation = next; conversationIncognito = false; conversationHistory = null;
      conversationPendingMessage = null; chatTerminal = null; chatLocalMessage = null;
    } on Object {
      if (epoch == _chatEpoch) chatLocalMessage = 'The conversation selection could not be saved.';
    } finally {
      if (epoch == _chatEpoch) { chatPending = false; _notify(); }
    }
  }

  void setConversationIncognito(bool value) {
    if (_disposed || _forgetting || chatPending || conversationNeedsRecovery || !conversationsAvailable) return;
    conversationIncognito = value; conversationHistory = null; chatTerminal = null;
    conversationPendingMessage = null; chatLocalMessage = null; _notify();
  }

  Future<void> _sendConversation(EnrollmentAccepted enrollment, String message) async {
    if (conversationNeedsRecovery) {
      chatLocalMessage = 'Recover the previous send first. No message will be sent again automatically.'; _notify(); return;
    }
    final current = _conversation ?? ConversationCheckpoint(deviceId: enrollment.deviceId, revision: enrollment.revision);
    if (!conversationIncognito && current.selectedId == null && current.conversationIds.length >= 8) {
      chatLocalMessage = 'This phone has eight saved conversations. Select one to continue.'; _notify(); return;
    }
    final requestId = freshConversationRequestId();
    final selected = conversationIncognito ? null : current.selectedId;
    final pending = ConversationCheckpoint(deviceId: enrollment.deviceId, revision: enrollment.revision,
      conversationIds: current.conversationIds, selectedId: current.selectedId, pendingRequestId: requestId,
      pendingConversationId: selected, pendingIncognito: conversationIncognito);
    final epoch = ++_chatEpoch;
    chatPending = true; chatCancelRequested = false; chatTerminal = null; chatPreview = null; chatActivity = null;
    _chatRequestId = requestId; _activityMaximum = -1; _activityIncomplete = false;
    conversationPendingMessage = message; chatLocalMessage = null; _notify();
    try {
      // The durable public request identity precedes every native/provider effect.
      await (_store as CompanionConversationStore).saveConversationCheckpoint(pending);
      if (_disposed || epoch != _chatEpoch) return;
      _conversation = pending;
      final action = selected == null
          ? <String, Object?>{'operation': 'new', 'message': message, 'incognito': conversationIncognito}
          : <String, Object?>{'operation': 'resume', 'message': message, 'conversation_id': selected};
      final command = jsonEncode({'command_schema_version': 1, 'request_id': requestId, 'revision': enrollment.revision, 'action': action});
      final result = await (_ensureBridge() as NativeBridgeWithConversation).conversation(
        jsonEncode(enrollment.reconnectDescriptor), enrollment.deviceId, command,
        (snapshot) => _acceptActivity(epoch, snapshot), (snapshot) => _acceptStream(epoch, snapshot));
      if (_disposed || epoch != _chatEpoch) return;
      final json = result.publicJson;
      if (json == null || json['kind'] != 'chat') {
        chatLocalMessage = 'The send outcome is unconfirmed. Recover saved history; the message will not be resent.'; return;
      }
      final terminal = CompanionChatTerminal.fromBridgeJson(json);
      if (terminal.requestId != requestId) throw const FormatException('foreign conversation terminal');
      ConversationAdmission? admission;
      if (json['conversation_admission'] case final Map<String, Object?> value) admission = ConversationAdmission.fromJson(value);
      ConversationHistory? history;
      if (json['conversation_history'] case final Map<String, Object?> value) history = ConversationHistory.fromJson(value);
      if (admission != null && (admission.requestId != requestId || admission.revision != enrollment.revision
          || admission.incognito != pending.pendingIncognito || (selected != null && admission.conversationId != selected))) throw const FormatException('foreign conversation admission');
      if (history != null && (admission == null || history.requestId != requestId || history.revision != enrollment.revision
          || history.conversationId != admission.conversationId || (history.state == 'incognito') != admission.incognito)) throw const FormatException('foreign conversation history');
      if (terminal.accepted && (admission == null || history == null)) throw const FormatException('missing conversation confirmation');
      final ids = [...current.conversationIds];
      final admittedId = admission?.conversationId;
      if (admittedId != null && !ids.contains(admittedId)) ids.add(admittedId);
      final unresolved = terminal.outcome == 'indeterminate';
      final next = ConversationCheckpoint(deviceId: enrollment.deviceId, revision: enrollment.revision, conversationIds: ids,
        selectedId: admittedId ?? current.selectedId, pendingRequestId: unresolved ? requestId : null,
        pendingConversationId: unresolved ? (admittedId ?? selected) : null, pendingIncognito: unresolved && pending.pendingIncognito);
      await (_store as CompanionConversationStore).saveConversationCheckpoint(next);
      if (_disposed || epoch != _chatEpoch) return;
      _conversation = next; chatTerminal = terminal; chatActivity = null; chatPreview = null;
      if (history != null) conversationHistory = history;
      if (history?.currentTurnCommitted == true) conversationPendingMessage = null;
      chatLocalMessage = unresolved ? 'The last send is unconfirmed. Recover history before continuing.' : null;
    } on Object {
      if (epoch == _chatEpoch) chatLocalMessage = 'The conversation could not be confirmed or saved. No message is retried.';
    } finally {
      if (epoch == _chatEpoch) { chatPreview = null; chatPending = false; chatCancelRequested = false; _notify(); }
    }
  }

  Future<void> recoverConversation() async {
    if (_disposed || _forgetting || chatPending || !conversationsAvailable) return;
    if (conversationIncognito && !conversationNeedsRecovery) return;
    final enrollment = _enrollment!;
    final current = _conversation;
    if (current == null || (current.pendingRequestId == null && current.selectedId == null)) return;
    final epoch = ++_chatEpoch;
    final requestId = freshConversationRequestId();
    chatPending = true; chatCancelRequested = false; chatPreview = null; chatActivity = null;
    _chatRequestId = requestId; _notify();
    try {
      ConversationHistory? history;
      if (!current.pendingIncognito) {
        final id = current.pendingConversationId ?? (current.pendingRequestId == null ? current.selectedId : null);
        final action = id == null
            ? {'operation': 'recover', 'created_by_request': current.pendingRequestId}
            : {'operation': 'history', 'conversation_id': id};
        final command = jsonEncode({'command_schema_version': 1, 'request_id': requestId, 'revision': enrollment.revision, 'action': action});
        final result = await (_ensureBridge() as NativeBridgeWithConversation).conversation(
          jsonEncode(enrollment.reconnectDescriptor), enrollment.deviceId, command, (_) {}, (_) {});
        if (_disposed || epoch != _chatEpoch) return;
        final json = result.publicJson;
        if (json == null || json['kind'] != 'conversation_history') throw const FormatException('history unavailable');
        history = ConversationHistory.fromJson(json);
        if (history.requestId != requestId || history.revision != enrollment.revision || history.currentTurnCommitted
            || history.state == 'incognito' || (id != null && history.conversationId != id)) throw const FormatException('foreign history');
      }
      final ids = [...current.conversationIds];
      final recoveredId = history?.conversationId;
      if (recoveredId != null && !ids.contains(recoveredId)) ids.add(recoveredId);
      final next = ConversationCheckpoint(deviceId: enrollment.deviceId, revision: enrollment.revision,
        conversationIds: ids, selectedId: recoveredId ?? current.selectedId);
      await (_store as CompanionConversationStore).saveConversationCheckpoint(next);
      if (_disposed || epoch != _chatEpoch) return;
      _conversation = next; conversationHistory = history; conversationPendingMessage = null; chatTerminal = null;
      chatLocalMessage = current.pendingIncognito ? 'Incognito has no saved history. The previous message will not be resent.'
          : current.pendingRequestId != null ? 'Saved history was checked. The previous send outcome remains unconfirmed; it will not be resent.'
          : history?.available == true ? null : 'Saved history is currently unavailable.';
    } on Object {
      if (epoch == _chatEpoch) chatLocalMessage = 'Saved history could not be verified. No provider request was sent.';
    } finally {
      if (epoch == _chatEpoch) { chatPending = false; chatCancelRequested = false; _notify(); }
    }
  }

  void _acceptStream(int epoch, CompanionChatStreamSnapshot snapshot) {
    if (_disposed || epoch != _chatEpoch || !chatPending || chatTerminal != null || chatCancelRequested) return;
    if (_chatRequestId != null && _chatRequestId != snapshot.requestId) return;
    if (snapshot.revision <= (chatPreview?.revision ?? 0)) return;
    _chatRequestId = snapshot.requestId;
    chatPreview = snapshot;
    _notify();
  }

  /// Stops waiting for this one local operation. This is not a provider or
  /// daemon abort claim: the bridge still owns the terminal poll and drain.
  Future<void> cancelChat() async {
    if (_disposed || !canStopWaiting) return;
    chatCancelRequested = true;
    chatPreview = null;
    chatLocalMessage = 'Stopping the wait…';
    _notify();
    // The native cancel call drains synchronously. Yield once so the disabled
    // control can render, then avoid signalling an operation whose terminal
    // already won this local cancellation race.
    await Future<void>.delayed(Duration.zero);
    if (_disposed || !chatPending || !chatCancelRequested) return;
    try {
      await _ensureBridge().cancelActiveChat();
    } on StateError {
      // A lifecycle close wins this race. The pending poll still owns cleanup.
    }
  }

  Future<void> forgetLocalEnrollment() async {
    if (_disposed || _forgetting) return;
    _forgetting = true;
    ++_authorityEpoch;
    _enrollment = null;
    status = null;
    // Invalidate before the awaited store mutation: a prior operation is still
    // owned and drained by native, but may not mutate this cleared session.
    ++_chatEpoch;
    _conversation = null; conversationHistory = null; conversationIncognito = false; conversationPendingMessage = null;
    chatPreview = null;
    _activityMaximum = -1;
    _activityIncomplete = false;
    chatPending = false;
    chatCancelRequested = false;
    chatActivity = null;
    chatTerminal = null;
    chatLocalMessage = null;
    _chatRequestId = null;
    final bridge = _bridge;
    if (bridge != null) unawaited(bridge.cancelActiveChat());
    try {
      await _store.clearEnrollment();
      _set(CompanionViewState.unpaired);
    } finally {
      _forgetting = false;
    }
  }

  NativeBridge _ensureBridge() => _bridge ?? (throw StateError('protected device identity is not ready'));

  Future<void> prepareBridge() async {
    if (_disposed || _bridge != null) return;
    final secret = await _store.loadOrCreateDeviceSecret();
    try {
      _bridge = _bridgeFactory(secret);
    } finally {
      secret.fillRange(0, secret.length, 0);
    }
  }

  void _setForResult(NativeBridgeResult result) {
    final code = result.publicJson?['code'];
    if (result.kind == NativeOperationResult.denied) {
      _set(code == 'revoked' ? CompanionViewState.revoked : CompanionViewState.denied);
    } else if (result.kind == NativeOperationResult.cancelled) {
      _set(CompanionViewState.offline);
    } else {
      _set(CompanionViewState.offline);
    }
  }

  void _set(CompanionViewState next) {
    if (_disposed) return;
    state = next;
    notifyListeners();
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    final bridge = _bridge;
    _bridge = null;
    if (bridge != null) {
      // The FFI owner cancels, reaches the terminal operation state, frees the
      // operation, and only then releases the native bridge allocation.
      unawaited(bridge.dispose());
    }
    super.dispose();
  }
}
