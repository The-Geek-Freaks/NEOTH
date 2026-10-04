import 'dart:convert';

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
    final body = _frameBody(json, 'enrollment_accepted');
    final scope = body['granted_scope'];
    final reconnect = body['reconnect'];
    if (scope != 'status_read' || reconnect is! Map<String, Object?>) {
      throw const FormatException('invalid public enrollment response');
    }
    return EnrollmentAccepted(
      deviceId: _uuid(body['device_id']),
      revision: _positiveInt(body['revision']),
      grantedScope: scope,
      reconnectDescriptor: reconnect,
    );
  }

  Map<String, String> toStorage() => <String, String>{
        'device_id': deviceId,
        'revision': '$revision',
        'granted_scope': grantedScope,
        'reconnect': jsonEncode(reconnectDescriptor),
      };
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
    final body = _frameBody(json, 'status_snapshot');
    final turns = body['active_turns'];
    if (turns != null && (turns is! List || turns.length > 8)) {
      throw const FormatException('invalid redacted status response');
    }
    return CompanionStatus(
      deviceId: _uuid(body['device_id']),
      daemonBootId: _boundedText(body['daemon_boot_id'], 128),
      readiness: _boundedText(body['readiness'], 32),
      observedAtUnix: _positiveInt(body['observed_at_unix']),
      activeTurns: turns == null ? null : turns.map((value) {
        if (value is! Map<String, Object?>) throw const FormatException('invalid active turn');
        final phase = value['phase'];
        final sequence = value['latest_sequence'];
        if (phase is! String || phase.isEmpty || utf8.encode(phase).length > 32 || sequence is! int || sequence < 0) {
          throw const FormatException('invalid active turn');
        }
        return value;
      }).toList(growable: false),
    );
  }
}

Map<String, Object?> _frameBody(Map<String, Object?> frame, String expectedType) {
  if (frame['type'] != expectedType || frame['body'] is! Map<String, Object?>) {
    throw const FormatException('unexpected bridge result');
  }
  final body = frame['body']! as Map<String, Object?>;
  if (body['schema_version'] != 3) throw const FormatException('unsupported companion schema');
  return body;
}

String _uuid(Object? value) {
  final text = _boundedText(value, 36);
  if (!RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$').hasMatch(text)) {
    throw const FormatException('invalid device identifier');
  }
  return text;
}

String _boundedText(Object? value, int maxLength) {
  if (value is! String || value.isEmpty || utf8.encode(value).length > maxLength) {
    throw const FormatException('invalid public bridge value');
  }
  return value;
}

int _positiveInt(Object? value) {
  if (value is! int || value < 1) throw const FormatException('invalid revision');
  return value;
}
