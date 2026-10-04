import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'bridge_input.dart';
import 'models.dart';

abstract interface class CompanionStore {
  Future<Uint8List> loadOrCreateDeviceSecret();
  Future<EnrollmentAccepted?> loadEnrollment();
  Future<void> saveEnrollment(EnrollmentAccepted enrollment);
  Future<void> clearEnrollment();
}

class SecureCompanionStore implements CompanionStore {
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
    if (id == null || revision == null ||
        (scope != companionStatusReadScope && scope != companionChatSendScope) || descriptor == null) {
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
    await _storage.writeAll(enrollment.toStorage().map((key, value) {
      switch (key) {
        case 'device_id': return MapEntry(_deviceIdKey, value);
        case 'revision': return MapEntry(_revisionKey, value);
        case 'granted_scope': return MapEntry(_scopeKey, value);
        case 'reconnect': return MapEntry(_descriptorKey, value);
        default: throw StateError('unexpected enrollment value');
      }
    }));
  }

  @override
  Future<void> clearEnrollment() async {
    // Retain the hardware-protected identity across a denied/revoked result.
    // The controller must never silently make a fresh pair with a new key.
    await _storage.delete(key: _deviceIdKey);
    await _storage.delete(key: _revisionKey);
    await _storage.delete(key: _scopeKey);
    await _storage.delete(key: _descriptorKey);
  }
}

Uint8List _decodeHex(String value) {
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(value)) return Uint8List(0);
  return Uint8List.fromList(List<int>.generate(32, (index) => int.parse(value.substring(index * 2, index * 2 + 2), radix: 16)));
}

String _hex(Uint8List bytes) => bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
