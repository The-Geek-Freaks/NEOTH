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
      expect(isBoundedReconnectInput('{}', '${_deviceId}é'), isFalse);
    });
  });
}

const _deviceId = '7fb8ae0f-9e36-4a64-83e2-972dff9af880';

String _repeat(String value, int count) => List<String>.filled(count, value).join();
