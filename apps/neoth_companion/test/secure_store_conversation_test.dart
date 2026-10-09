import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/conversation_models.dart';
import 'package:neoth_companion/secure_store.dart';

const _deviceId = '7fb8ae0f-9e36-4a64-83e2-972dff9af880';
const _requestId = '00000000-0000-4000-8000-000000000001';
const _checkpointKey = 'neoth_companion.conversation.v1';
const _secretKey = 'neoth_companion.device_secret.v1';
const _channel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final failWrite in [false, true]) {
    test(failWrite
        ? 'JM05 protected checkpoint failure is reported while queued forget still clears authority'
        : 'JM05 protected checkpoint cannot reappear after forget completes', () async {
      final values = <String, String>{
        _secretKey: List.filled(64, 'a').join(),
        'neoth_companion.device_id.v3': _deviceId,
        'neoth_companion.revision.v3': '3',
        'neoth_companion.scope.v3': 'companion.chat.send',
        'neoth_companion.reconnect.v3': jsonEncode({
          'schema_version': 3, 'carrier': 'peeroxide-hyperswarm-v3',
          'rendezvous_topic_hex': List.filled(64, 'a').join(),
          'daemon_noise_public_key_hex': List.filled(64, 'b').join(), 'descriptor_generation': 1,
        }),
      };
      final entered = Completer<void>();
      final release = Completer<void>();
      final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      messenger.setMockMethodCallHandler(_channel, (call) async {
        final args = call.arguments as Map;
        final key = args['key'];
        switch (call.method) {
          case 'readAll': return Map<String, String>.from(values);
          case 'read': return values[key];
          case 'delete': values.remove(key); return null;
          case 'write':
            if (key == _checkpointKey) {
              entered.complete();
              await release.future;
              if (failWrite) throw PlatformException(code: 'fixture_write_failed');
            }
            values[key as String] = args['value'] as String;
            return null;
          default: throw StateError('unexpected storage method');
        }
      });
      addTearDown(() => messenger.setMockMethodCallHandler(_channel, null));
      final store = SecureCompanionStore(const FlutterSecureStorage());
      final saving = store.saveConversationCheckpoint(ConversationCheckpoint(
        deviceId: _deviceId, revision: 3, pendingRequestId: _requestId));
      final saveObserved = failWrite
          ? expectLater(saving, throwsA(isA<PlatformException>()))
          : saving;
      await entered.future;
      var cleared = false;
      final clearing = store.clearEnrollment().then((_) { cleared = true; });
      await Future<void>.delayed(Duration.zero);
      expect(cleared, isFalse);
      release.complete();
      await saveObserved;
      await clearing;
      expect(values.keys, [_secretKey]);
      expect(await store.loadEnrollment(), isNull);
      expect(values.containsKey(_checkpointKey), isFalse);
    });
  }
}
