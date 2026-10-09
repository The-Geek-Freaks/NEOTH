import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'bridge_input.dart';
import 'models.dart';
import 'conversation_models.dart';

abstract interface class CompanionStore {
  Future<Uint8List> loadOrCreateDeviceSecret();
  Future<EnrollmentAccepted?> loadEnrollment();
  Future<void> saveEnrollment(EnrollmentAccepted enrollment);
  Future<void> clearEnrollment();
}

abstract interface class CompanionConversationStore implements CompanionStore {
  Future<ConversationCheckpoint?> loadConversationCheckpoint(EnrollmentAccepted enrollment);
  Future<void> saveConversationCheckpoint(ConversationCheckpoint checkpoint);
}

class SecureCompanionStore implements CompanionConversationStore {
  SecureCompanionStore([FlutterSecureStorage? storage])
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
            );

  static const _secretKey = 'neoth_companion.device_secret.v1';
  static const _deviceIdKey = 'neoth_companion.device_id.v3';
  static const _revisionKey = 'neoth_companion.revision.v3';
  static const _scopeKey = 'neoth_companion.scope.v3';
  static const _descriptorKey = 'neoth_companion.reconnect.v3';
  static const _conversationKey = 'neoth_companion.conversation.v1';
  final FlutterSecureStorage _storage;

  @override
  Future<Uint8List> loadOrCreateDeviceSecret() async {
    final existing = await _storage.read(key: _secretKey);
    if (existing != null) {
      final parsed = _decodeHex(existing);
      if (parsed.length == 32) return parsed;
      await _storage.delete(key: _secretKey);
    }
    final secret = Uint8List.fromList(List<int>.generate(32, (_) => Random.secure().nextInt(256)));
    await _storage.write(key: _secretKey, value: _hex(secret));
    return secret;
  }

  @override
  Future<EnrollmentAccepted?> loadEnrollment() async {
    final values = await _storage.readAll();
    final id = values[_deviceIdKey];
    final revision = int.tryParse(values[_revisionKey] ?? '');
    final scope = values[_scopeKey];
    final descriptor = values[_descriptorKey];
    if (id == null && revision == null && scope == null && descriptor == null) return null;
    if (id == null ||
        revision == null ||
        scope is! String ||
        (scope != companionStatusReadScope && scope != companionChatSendScope) ||
        descriptor == null) {
      await clearEnrollment();
      return null;
    }
    try {
      final decoded = jsonDecode(descriptor);
      if (decoded is! Map<String, Object?>) throw const FormatException('descriptor');
      return EnrollmentAccepted(deviceId: id, revision: revision, grantedScope: scope, reconnectDescriptor: decoded);
    } on FormatException {
      await clearEnrollment();
      return null;
    }
  }

  @override
  Future<void> saveEnrollment(EnrollmentAccepted enrollment) async {
    // The device id is the enrollment commit marker. Clearing it first means
    // an interrupted update cannot combine a new descriptor with an old id.
    // The protected device secret remains intact for a deliberate retry.
    await _storage.delete(key: _deviceIdKey);
    await _storage.delete(key: _conversationKey);
    await _storage.write(key: _revisionKey, value: '${enrollment.revision}');
    await _storage.write(key: _scopeKey, value: enrollment.grantedScope);
    await _storage.write(key: _descriptorKey, value: jsonEncode(enrollment.reconnectDescriptor));
    await _storage.write(key: _deviceIdKey, value: enrollment.deviceId);
  }

  @override
  Future<void> clearEnrollment() async {
    // Retain the hardware-protected identity across a denied/revoked result.
    // The controller must never silently make a fresh pair with a new key.
    await _storage.delete(key: _deviceIdKey);
    await _storage.delete(key: _revisionKey);
    await _storage.delete(key: _scopeKey);
    await _storage.delete(key: _descriptorKey);
    await _storage.delete(key: _conversationKey);
  }

  @override
  Future<ConversationCheckpoint?> loadConversationCheckpoint(EnrollmentAccepted enrollment) async {
    final encoded = await _storage.read(key: _conversationKey);
    if (encoded == null) return null;
    try {
      if (utf8.encode(encoded).length > 4096) throw const FormatException('checkpoint size');
      final value = jsonDecode(encoded);
      if (value is! Map<String, Object?>) throw const FormatException('checkpoint object');
      final checkpoint = ConversationCheckpoint.fromJson(value);
      if (checkpoint.deviceId != enrollment.deviceId || checkpoint.revision != enrollment.revision) throw const FormatException('checkpoint scope');
      return checkpoint;
    } on FormatException {
      await _storage.delete(key: _conversationKey);
      return null;
    }
  }

  @override
  Future<void> saveConversationCheckpoint(ConversationCheckpoint checkpoint) async {
    final encoded = jsonEncode(checkpoint.toJson());
    if (utf8.encode(encoded).length > 4096) throw const FormatException('checkpoint size');
    final enrollment = await loadEnrollment();
    if (enrollment == null || enrollment.deviceId != checkpoint.deviceId || enrollment.revision != checkpoint.revision) throw StateError('conversation enrollment changed');
    await _storage.write(key: _conversationKey, value: encoded);
  }
}

Uint8List _decodeHex(String value) {
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(value)) return Uint8List(0);
  return Uint8List.fromList(List<int>.generate(32, (index) => int.parse(value.substring(index * 2, index * 2 + 2), radix: 16)));
}

String _hex(Uint8List bytes) => bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
