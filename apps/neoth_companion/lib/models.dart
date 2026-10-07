import 'dart:convert';

import 'bridge_input.dart';

enum CompanionViewState { unpaired, pairing, ready, offline, denied, revoked, failed }

class EnrollmentAccepted {
  const EnrollmentAccepted({
    required this.deviceId,
    required this.revision,
    required this.grantedScope,
    required this.reconnectDescriptor,
  });

  final String deviceId;
  final int revision;
  final String grantedScope;
  final Map<String, Object?> reconnectDescriptor;

  factory EnrollmentAccepted.fromBridgeJson(Map<String, Object?> json) {
    if (json['state'] != 'paired') throw const FormatException('unexpected bridge enrollment result');
    final scope = json['granted_scope'];
    final reconnect = json['descriptor'];
    if (scope is! String ||
        (scope != companionStatusReadScope && scope != companionChatSendScope) ||
        reconnect is! Map<String, Object?>) {
      throw const FormatException('invalid public enrollment response');
    }
    return EnrollmentAccepted(
      deviceId: _uuid(json['device_id']),
      revision: _positiveInt(json['revision']),
      grantedScope: scope,
      reconnectDescriptor: _publicDescriptor(reconnect),
    );
  }

  Map<String, String> toStorage() => <String, String>{
        'device_id': deviceId,
        'revision': '$revision',
        'granted_scope': grantedScope,
        'reconnect': jsonEncode(reconnectDescriptor),
      };
}

class CompanionChatTerminal {
  const CompanionChatTerminal({
    required this.requestId,
    required this.outcome,
    required this.records,
    this.provider,
    this.model,
  });

  final String requestId;
  final String outcome;
  final List<CompanionChatRecord> records;
  final String? provider;
  final String? model;

  bool get accepted => outcome == 'accepted';

  factory CompanionChatTerminal.fromBridgeJson(Map<String, Object?> json) {
    if (json['kind'] != 'chat' || json['schema_version'] != 3) {
      throw const FormatException('unexpected chat bridge result');
    }
    final outcome = json['outcome'];
    const allowedOutcomes = <String>{'accepted', 'denied', 'busy', 'unavailable', 'timeout', 'indeterminate'};
    if (outcome is! String || !allowedOutcomes.contains(outcome)) {
      throw const FormatException('invalid chat outcome');
    }
    final values = json['records'];
    if (values is! List || values.length > 64) throw const FormatException('invalid chat records');
    final records = values.map((value) {
      if (value is! Map<String, Object?>) throw const FormatException('invalid chat record');
      return CompanionChatRecord.fromJson(value);
    }).toList(growable: false);
    final provider = json['provider'];
    final model = json['model'];
    if (outcome == 'accepted') {
      if (provider is! String || model is! String || provider.isEmpty || model.isEmpty) {
        throw const FormatException('accepted chat terminal lacks model custody');
      }
      return CompanionChatTerminal(
        requestId: _uuid(json['request_id']),
        outcome: outcome,
        records: records,
        provider: _boundedText(provider, 256),
        model: _boundedText(model, 256),
      );
    }
    if (provider != null || model != null || records.isNotEmpty) {
      throw const FormatException('nonaccepted chat terminal leaks response data');
    }
    return CompanionChatTerminal(requestId: _uuid(json['request_id']), outcome: outcome, records: records);
  }

  factory CompanionChatTerminal.indeterminate() => const CompanionChatTerminal(
        requestId: '00000000-0000-0000-0000-000000000000',
        outcome: 'indeterminate',
        records: <CompanionChatRecord>[],
      );
}

class CompanionChatRecord {
  const CompanionChatRecord({required this.kind, required this.text});

  final String kind;
  final String text;

  factory CompanionChatRecord.fromJson(Map<String, Object?> json) {
    final kind = json['kind'];
    if (kind is! String || !const <String>{'stdout', 'stderr', 'notice'}.contains(kind)) {
      throw const FormatException('invalid chat record kind');
    }
    return CompanionChatRecord(kind: kind, text: _boundedMaybeEmptyText(json['text'], 80 * 1024));
  }
}

class CompanionStatus {
  const CompanionStatus({
    required this.deviceId,
    required this.daemonBootId,
    required this.readiness,
    required this.observedAtUnix,
    required this.activeTurns,
  });

  final String deviceId;
  final String daemonBootId;
  final String readiness;
  final int observedAtUnix;
  /// `null` is an honest unavailable observation; it is deliberately not
  /// converted into an empty list of active work.
  final List<Map<String, Object?>>? activeTurns;

  factory CompanionStatus.fromBridgeJson(Map<String, Object?> json) {
    if (json['state'] != 'status') throw const FormatException('unexpected bridge status result');
    final turns = json['active_turns'];
    final List<Map<String, Object?>>? activeTurns;
    if (turns == null) {
      activeTurns = null;
    } else {
      if (turns is! List || turns.length > 8) {
        throw const FormatException('invalid redacted status response');
      }
      activeTurns = turns.map((value) {
        if (value is! Map<String, Object?>) throw const FormatException('invalid active turn');
        final phase = value['phase'];
        final sequence = value['latest_sequence'];
        if (phase is! String || phase.isEmpty || utf8.encode(phase).length > 32 || sequence is! int || sequence < 0) {
          throw const FormatException('invalid active turn');
        }
        return value;
      }).toList(growable: false);
    }
    return CompanionStatus(
      deviceId: _uuid(json['device_id']),
      daemonBootId: _boundedText(json['daemon_boot_id'], 128),
      readiness: _boundedText(json['readiness'], 32),
      observedAtUnix: _positiveInt(json['observed_at_unix']),
      activeTurns: activeTurns,
    );
  }
}

String _uuid(Object? value) {
  final text = _boundedText(value, 36);
  if (!RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$').hasMatch(text)) {
    throw const FormatException('invalid device identifier');
  }
  return text;
}

Map<String, Object?> _publicDescriptor(Map<String, Object?> value) {
  if (value['schema_version'] != 3 ||
      _boundedText(value['carrier'], 64) != 'peeroxide-hyperswarm-v3' ||
      !_lowerHex(value['rendezvous_topic_hex'], 64) ||
      !_lowerHex(value['daemon_noise_public_key_hex'], 64) ||
      _positiveInt(value['descriptor_generation']) < 1) {
    throw const FormatException('invalid public reconnect descriptor');
  }
  return value;
}

bool _lowerHex(Object? value, int length) =>
    value is String && value.length == length && RegExp('^[0-9a-f]{$length}\$').hasMatch(value);

String _boundedText(Object? value, int maxLength) {
  if (value is! String || value.isEmpty || utf8.encode(value).length > maxLength) {
    throw const FormatException('invalid public bridge value');
  }
  return value;
}

String _boundedMaybeEmptyText(Object? value, int maxLength) {
  if (value is! String || utf8.encode(value).length > maxLength) {
    throw const FormatException('invalid public bridge value');
  }
  return value;
}

int _positiveInt(Object? value) {
  if (value is! int || value < 1) throw const FormatException('invalid revision');
  return value;
}

enum CompanionToolActivityPhase { started, succeeded, failed, rejected, unknown }

class CompanionToolActivityEvent {
  const CompanionToolActivityEvent({required this.eventSeq, required this.ordinal, required this.phase, required this.label});
  final int eventSeq;
  final int ordinal;
  final CompanionToolActivityPhase phase;
  final String label;

  factory CompanionToolActivityEvent.fromJson(Map<String, Object?> value, int prior) {
    const keys = {'event_seq', 'ordinal', 'phase', 'label'};
    if (value.length != keys.length || !value.keys.toSet().containsAll(keys)) throw const FormatException('unexpected activity event');
    final sequence = value['event_seq']; final ordinal = value['ordinal']; final phase = value['phase']; final label = value['label'];
    const labels = {'Read file', 'Write file', 'List files', 'Search code', 'Tool call'};
    if (sequence is! int || sequence <= prior || ordinal is! int || ordinal < 1 || phase is! String || label is! String ||
        !labels.contains(label) || utf8.encode(label).length > 96 || label.runes.any((rune) => rune < 0x20 || rune == 0x7f)) {
      throw const FormatException('invalid activity event');
    }
    final parsed = switch (phase) {
      'started' => CompanionToolActivityPhase.started, 'succeeded' => CompanionToolActivityPhase.succeeded,
      'failed' => CompanionToolActivityPhase.failed, 'rejected' => CompanionToolActivityPhase.rejected,
      'unknown' => CompanionToolActivityPhase.unknown, _ => throw const FormatException('invalid activity phase'),
    };
    return CompanionToolActivityEvent(eventSeq: sequence, ordinal: ordinal, phase: parsed, label: label);
  }
}

class CompanionChatActivitySnapshot {
  const CompanionChatActivitySnapshot({required this.requestId, required this.maxEventSeq, required this.incomplete, required this.events});
  final String requestId; final int maxEventSeq; final bool incomplete; final List<CompanionToolActivityEvent> events;
  factory CompanionChatActivitySnapshot.fromBridgeJson(Map<String, Object?> value) {
    const keys = {'kind', 'activity_schema_version', 'request_id', 'max_event_seq', 'incomplete', 'events'};
    if (value.length != keys.length || !value.keys.toSet().containsAll(keys) || value['kind'] != 'chat_activity_snapshot' || value['activity_schema_version'] != 1) throw const FormatException('unexpected activity snapshot');
    final maximum = value['max_event_seq']; final incomplete = value['incomplete']; final raw = value['events'];
    if (maximum is! int || maximum < 0 || incomplete is! bool || raw is! List || raw.length > 16) throw const FormatException('invalid activity snapshot');
    var prior = 0; final events = <CompanionToolActivityEvent>[];
    for (final entry in raw) { if (entry is! Map<String, Object?>) throw const FormatException('invalid activity event'); final parsed = CompanionToolActivityEvent.fromJson(entry, prior); prior = parsed.eventSeq; events.add(parsed); }
    if (maximum != prior) throw const FormatException('invalid activity maximum');
    return CompanionChatActivitySnapshot(requestId: _uuid(value['request_id']), maxEventSeq: maximum, incomplete: incomplete, events: List.unmodifiable(events));
  }
}
