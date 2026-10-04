import 'package:flutter_test/flutter_test.dart';
import 'package:neoth_companion/bridge_input.dart';

void main() {
  group('bridge UTF-8 input limits', () {
    test('accepts a 64-byte multibyte device label and rejects 66 bytes', () {
      expect(() => validateLabel(_repeat('é', 32)), returnsNormally);
      expect(() => validateLabel(_repeat('é', 33)), throwsFormatException);
    });

    test('counts descriptor bytes rather than UTF-16 code units', () {
      expect(isBoundedReconnectInput(_repeat('é', 4096), _deviceId), isTrue);
      expect(isBoundedReconnectInput(_repeat('é', 4097), _deviceId), isFalse);
    });

    test('rejects Unicode even where a code-unit length might look bounded for an invite', () {
      expect(() => validateInvite(_repeat('é', 256)), throwsFormatException);
    });

    test('requires the public UUID to fit the 36-byte ABI field', () {
      expect(isBoundedReconnectInput('{}', _deviceId), isTrue);
      expect(isBoundedReconnectInput('{}', '$_deviceIdé'), isFalse);
    });

    test('accepts the 640-byte ordinary chat limit and rejects a multibyte overflow', () {
      expect(() => validateOrdinaryChatMessage(_repeat('a', 640)), returnsNormally);
      expect(() => validateOrdinaryChatMessage(_repeat('é', 321)), throwsFormatException);
    });

    test('rejects a slash action after leading whitespace before bridge start', () {
      expect(() => validateOrdinaryChatMessage('  /status'), throwsFormatException);
      expect(() => validateOrdinaryChatMessage('  ordinary text'), returnsNormally);
    });

    test('accepts only absent status-default or one explicit allowlisted v3 scope', () {
      expect(() => validateInvite(_inviteWithScope), returnsNormally);
      expect(() => validateInvite(_inviteWithoutScope), returnsNormally);
      expect(() => validateInvite('$_inviteWithoutScope&scope=companion.chat.send&scope=companion.chat.send'), throwsFormatException);
      expect(() => validateInvite('$_inviteWithoutScope&scope=companion.files.read'), throwsFormatException);
    });
  });
}

const _deviceId = '7fb8ae0f-9e36-4a64-83e2-972dff9af880';
const _inviteWithoutScope = 'neoth://companion/pair?v=3&topic=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&psk=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb&server_pk=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc&ttl=60';
const _inviteWithScope = '$_inviteWithoutScope&scope=companion.chat.send';

String _repeat(String value, int count) => List<String>.filled(count, value).join();
