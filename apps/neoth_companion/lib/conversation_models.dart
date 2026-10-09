import 'dart:convert';
import 'dart:math';

String conversationUuid(Object? value) {
  if (value is! String || !RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$').hasMatch(value)
      || value == '00000000-0000-0000-0000-000000000000') throw const FormatException('invalid public conversation identity');
  return value;
}

String freshConversationRequestId() {
  final random = Random.secure();
  final bytes = List<int>.generate(16, (_) => random.nextInt(256));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  final hex = bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

int _revision(Object? value) {
  if (value is! int || value < 1) throw const FormatException('invalid conversation revision');
  return value;
}

void _keys(Map<String, Object?> json, Set<String> keys) {
  if (json.keys.any((key) => !keys.contains(key))) throw const FormatException('unknown conversation field');
}

class ConversationAdmission {
  const ConversationAdmission({required this.requestId, required this.revision, required this.conversationId, required this.incognito});
  final String requestId;
  final int revision;
  final String? conversationId;
  final bool incognito;

  factory ConversationAdmission.fromJson(Map<String, Object?> json) {
    _keys(json, {'conversation_schema_version', 'request_id', 'revision', 'conversation_id', 'incognito'});
    if (json['conversation_schema_version'] != 1 || json['incognito'] is! bool) throw const FormatException('conversation admission');
    final id = json['conversation_id'] == null ? null : conversationUuid(json['conversation_id']);
    final incognito = json['incognito']! as bool;
    if (incognito != (id == null)) throw const FormatException('incognito admission');
    return ConversationAdmission(requestId: conversationUuid(json['request_id']), revision: _revision(json['revision']), conversationId: id, incognito: incognito);
  }
}

class ConversationTurn {
  const ConversationTurn({required this.role, required this.text, required this.truncated});
  final String role;
  final String? text;
  final bool truncated;
}

class ConversationHistory {
  const ConversationHistory({required this.requestId, required this.revision, required this.conversationId,
    required this.state, required this.currentTurnCommitted, required this.turns});
  final String requestId;
  final int revision;
  final String? conversationId;
  final String state;
  final bool currentTurnCommitted;
  final List<ConversationTurn> turns;
  bool get available => state == 'available';

  factory ConversationHistory.fromJson(Map<String, Object?> json) {
    _keys(json, {'kind', 'conversation_schema_version', 'request_id', 'revision', 'conversation_id', 'state', 'current_turn_committed', 'bounded_tail', 'turns'});
    if (json['kind'] != null && json['kind'] != 'conversation_history') throw const FormatException('history kind');
    final state = json['state'];
    if (json['conversation_schema_version'] != 1 || json['bounded_tail'] != true || json['current_turn_committed'] is! bool
        || !{'available', 'unavailable', 'not_found', 'incognito'}.contains(state)) throw const FormatException('conversation history');
    final id = json['conversation_id'] == null ? null : conversationUuid(json['conversation_id']);
    if ((state == 'available' || state == 'unavailable') != (id != null)) throw const FormatException('history identity');
    final values = json['turns'];
    if (values is! List || values.length > 32 || utf8.encode(jsonEncode(values)).length > 96 * 1024) throw const FormatException('history bounds');
    var bytes = 0;
    final turns = <ConversationTurn>[];
    for (final value in values) {
      if (value is! Map<String, Object?>) throw const FormatException('history row');
      _keys(value, {'role', 'text', 'truncated'});
      final role = value['role']; final text = value['text']; final truncated = value['truncated'];
      if ((role != 'operator' && role != 'agent') || (text != null && text is! String)
          || truncated is! bool || truncated != (text == null)) throw const FormatException('history row fields');
      final size = text is String ? utf8.encode(text).length : 0;
      bytes += size;
      if (size > 16384 || bytes > 65536) throw const FormatException('history text bounds');
      turns.add(ConversationTurn(role: role! as String, text: text as String?, truncated: truncated));
    }
    final committed = json['current_turn_committed']! as bool;
    if (state != 'available' && (turns.isNotEmpty || committed)) throw const FormatException('unavailable history');
    return ConversationHistory(requestId: conversationUuid(json['request_id']), revision: _revision(json['revision']), conversationId: id,
      state: state! as String, currentTurnCommitted: committed, turns: List.unmodifiable(turns));
  }
}

/// Only public identifiers survive a restart. Prompts, answers and private
/// daemon session IDs are never stored by this checkpoint.
class ConversationCheckpoint {
  ConversationCheckpoint({required this.deviceId, required this.revision, List<String> conversationIds = const [],
    this.selectedId, this.pendingRequestId, this.pendingConversationId, this.pendingIncognito = false})
      : conversationIds = List.unmodifiable(conversationIds) {
    conversationUuid(deviceId); _revision(revision);
    if (conversationIds.length > 8 || conversationIds.toSet().length != conversationIds.length) throw const FormatException('conversation capacity');
    for (final id in conversationIds) { conversationUuid(id); }
    for (final id in [selectedId, pendingRequestId, pendingConversationId]) { if (id != null) conversationUuid(id); }
    if (selectedId != null && !conversationIds.contains(selectedId)) throw const FormatException('unknown selected conversation');
    if (pendingRequestId == null && (pendingConversationId != null || pendingIncognito)) throw const FormatException('orphan pending conversation');
    if (pendingIncognito && pendingConversationId != null) throw const FormatException('incognito conversation binding');
    if (pendingConversationId != null && !conversationIds.contains(pendingConversationId)) throw const FormatException('unknown pending conversation');
  }
  final String deviceId;
  final int revision;
  final List<String> conversationIds;
  final String? selectedId;
  final String? pendingRequestId;
  final String? pendingConversationId;
  final bool pendingIncognito;

  Map<String, Object?> toJson() => {'schema_version': 1, 'device_id': deviceId, 'revision': revision,
    'conversation_ids': conversationIds, 'selected_id': selectedId, 'pending_request_id': pendingRequestId,
    'pending_conversation_id': pendingConversationId, 'pending_incognito': pendingIncognito};

  factory ConversationCheckpoint.fromJson(Map<String, Object?> json) {
    _keys(json, {'schema_version', 'device_id', 'revision', 'conversation_ids', 'selected_id', 'pending_request_id', 'pending_conversation_id', 'pending_incognito'});
    if (json['schema_version'] != 1 || json['conversation_ids'] is! List || json['pending_incognito'] is! bool) throw const FormatException('checkpoint');
    String? optional(String key) => json[key] == null ? null : conversationUuid(json[key]);
    return ConversationCheckpoint(deviceId: conversationUuid(json['device_id']), revision: _revision(json['revision']),
      conversationIds: (json['conversation_ids']! as List).map(conversationUuid).toList(), selectedId: optional('selected_id'),
      pendingRequestId: optional('pending_request_id'), pendingConversationId: optional('pending_conversation_id'), pendingIncognito: json['pending_incognito']! as bool);
  }
}
