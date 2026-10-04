import 'dart:convert';

final companionDeviceId = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');
final companionInvite = RegExp(r'^neoth://companion/pair\?v=3&topic=[0-9a-f]{64}&psk=[0-9a-f]{32}&server_pk=[0-9a-f]{64}&ttl=([1-9]|[1-9][0-9]|[12][0-9]{2}|300)(?:&scope=companion\.(?:status\.read|chat\.send))?$');

const companionStatusReadScope = 'companion.status.read';
const companionChatSendScope = 'companion.chat.send';
const companionChatMessageMaxBytes = 640;

int utf8ByteLength(String value) => utf8.encode(value).length;

void validateInvite(String value) {
  if (utf8ByteLength(value) > 512 || !companionInvite.hasMatch(value)) {
    throw const FormatException('invalid companion invitation');
  }
}

void validateLabel(String value) {
  if (value.isEmpty || utf8ByteLength(value) > 64 || value.runes.any((rune) => rune < 0x20 || rune == 0x7f)) {
    throw const FormatException('invalid device label');
  }
}

bool isBoundedReconnectInput(String descriptorJson, String deviceId) {
  return descriptorJson.isNotEmpty &&
      utf8ByteLength(descriptorJson) <= 8192 &&
      utf8ByteLength(deviceId) <= 36 &&
      companionDeviceId.hasMatch(deviceId);
}

/// This is intentionally the same small ordinary-text boundary as the daemon
/// plain-chat contract. It permits ordinary whitespace, but never a local
/// slash action after leading whitespace.
void validateOrdinaryChatMessage(String value) {
  if (value.isEmpty || utf8ByteLength(value) > companionChatMessageMaxBytes || value.trimLeft().startsWith('/')) {
    throw const FormatException('invalid ordinary chat message');
  }
}
