#ifndef NEOTH_COMPANION_BRIDGE_H
#define NEOTH_COMPANION_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct neoth_companion_bridge neoth_companion_bridge;
typedef struct neoth_companion_operation neoth_companion_operation;

enum neoth_companion_result {
  NEOTH_COMPANION_PENDING = 0,
  NEOTH_COMPANION_OK = 1,
  NEOTH_COMPANION_DENIED = 2,
  NEOTH_COMPANION_FAILED = 3,
  NEOTH_COMPANION_CANCELLED = 4,
  NEOTH_COMPANION_BUFFER_TOO_SMALL = 5,
  NEOTH_COMPANION_INTERNAL = -1
};

/* `device_secret` is exactly 32 bytes supplied from Android Keystore/iOS
 * Keychain. It is copied then zeroed by the caller; no key is returned. */
neoth_companion_bridge *neoth_companion_bridge_new(
    const uint8_t *device_secret, size_t device_secret_len);
void neoth_companion_bridge_free(neoth_companion_bridge *bridge);

/* Pair URL must be a bounded v=3 invite. `label` is a bounded display label.
 * Returned operation emits only a public reconnect descriptor or error code. */
neoth_companion_operation *neoth_companion_pair_start(
    neoth_companion_bridge *bridge, const uint8_t *pair_url, size_t pair_url_len,
    const uint8_t *label, size_t label_len);

/* Reconnect consumes the exact public descriptor returned by pair plus the
 * public persisted device UUID. The v3 daemon maps the authenticated client
 * Noise key itself; no bearer or device-selector wire frame exists. */
neoth_companion_operation *neoth_companion_reconnect_start(
    neoth_companion_bridge *bridge, const uint8_t *descriptor_json,
    size_t descriptor_json_len, const uint8_t *device_id, size_t device_id_len);

/* Poll is non-blocking. On terminal state it writes bounded UTF-8 JSON public
 * result bytes to `out`; set `out` NULL/0 to discover required length. The
 * buffer is byte-counted and has no trailing NUL. Size discovery returns
 * NEOTH_COMPANION_BUFFER_TOO_SMALL for every terminal result; inspect
 * required_len, retry with that capacity, then receive its real terminal code.
 * `cancel` blocks until the owned transport worker has drained and a terminal
 * poll result is available; it never requires a separate drain call. */
int32_t neoth_companion_operation_poll(neoth_companion_operation *operation,
    uint8_t *out, size_t out_len, size_t *required_len);
void neoth_companion_operation_cancel(neoth_companion_operation *operation);
void neoth_companion_operation_free(neoth_companion_operation *operation);

#ifdef __cplusplus
}
#endif
#endif
