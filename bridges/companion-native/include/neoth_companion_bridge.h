#ifndef NEOTH_COMPANION_BRIDGE_H
#define NEOTH_COMPANION_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct neoth_companion_bridge neoth_companion_bridge;
typedef struct neoth_companion_operation neoth_companion_operation;

/* All opaque pointers have one owner. Calls using, cancelling, or freeing the
 * same bridge/operation must be serialized by the caller. Do not free a bridge
 * while its operations remain live, or alias `free` with `poll`/`cancel`. */

enum neoth_companion_result {
  NEOTH_COMPANION_PENDING = 0,
  NEOTH_COMPANION_OK = 1,
  NEOTH_COMPANION_DENIED = 2,
  NEOTH_COMPANION_FAILED = 3,
  NEOTH_COMPANION_CANCELLED = 4,
  NEOTH_COMPANION_BUFFER_TOO_SMALL = 5,
  /* A bounded capability-negotiated chat activity snapshot. This is only
   * returned by `neoth_companion_operation_poll_v2`; it is not terminal. */
  NEOTH_COMPANION_ACTIVITY = 6,
  NEOTH_COMPANION_INTERNAL = -1
};

/* `device_secret` is exactly 32 bytes supplied from Android Keystore/iOS
 * Keychain. It is copied then zeroed by the caller; no key is returned. */
neoth_companion_bridge *neoth_companion_bridge_new(
    const uint8_t *device_secret, size_t device_secret_len);
void neoth_companion_bridge_free(neoth_companion_bridge *bridge);

/* Pair URL must be a bounded v=3 invite. `label` is a bounded display label.
 * Its terminal public JSON is flat `state:"paired"`, with `device_id`,
 * `revision`, stable `granted_scope`, and a public descriptor containing
 * hex topic/key fields; it is not a daemon `ServerFrame` envelope. */
neoth_companion_operation *neoth_companion_pair_start(
    neoth_companion_bridge *bridge, const uint8_t *pair_url, size_t pair_url_len,
    const uint8_t *label, size_t label_len);

/* Reconnect consumes the exact public descriptor returned by pair plus the
 * public persisted device UUID. The v3 daemon maps the authenticated client
 * Noise key itself; no bearer or device-selector wire frame exists. */
neoth_companion_operation *neoth_companion_reconnect_start(
    neoth_companion_bridge *bridge, const uint8_t *descriptor_json,
    size_t descriptor_json_len, const uint8_t *device_id, size_t device_id_len);

/* One fresh chat turn over a chat-scoped reconnect descriptor. `message` is
 * UTF-8, 1..640 bytes, and must not begin with `/` after leading whitespace.
 * There is no retry. A post-send transport ambiguity is terminal JSON outcome
 * `indeterminate`; no secret, session, bearer, or provider request id crosses
 * this ABI. */
neoth_companion_operation *neoth_companion_chat_start(
    neoth_companion_bridge *bridge, const uint8_t *descriptor_json,
    size_t descriptor_json_len, const uint8_t *device_id, size_t device_id_len,
    const uint8_t *message, size_t message_len);

/* Additive activity-capable chat start. The original `chat_start` remains
 * terminal-only. `request_tool_activity` must be 0 or 1. A value of 1 is an
 * opt-in request only: the bridge signs it only after the encrypted server
 * ChatChallenge advertises support. An old or non-advertising daemon receives
 * the exact legacy signed request and produces the usual one terminal result;
 * no prompt is replayed. */
neoth_companion_operation *neoth_companion_chat_start_v2(
    neoth_companion_bridge *bridge, const uint8_t *descriptor_json,
    size_t descriptor_json_len, const uint8_t *device_id, size_t device_id_len,
    const uint8_t *message, size_t message_len, uint8_t request_tool_activity);

/* Poll is non-blocking. On terminal state it writes bounded UTF-8 JSON public
 * result bytes to `out`; set `out` NULL/0 to discover required length. The
 * buffer is byte-counted and has no trailing NUL. Size discovery returns
 * NEOTH_COMPANION_BUFFER_TOO_SMALL for every terminal result; inspect
 * required_len, retry with that capacity, then receive its real terminal code.
 * `cancel` blocks until the owned transport worker has drained and a terminal
 * poll result is available; it never requires a separate drain call. */
int32_t neoth_companion_operation_poll(neoth_companion_operation *operation,
    uint8_t *out, size_t out_len, size_t *required_len);

/* Additive non-blocking poll. It preserves all v1 terminal codes and buffer
 * discovery semantics. Code NEOTH_COMPANION_ACTIVITY carries a bounded
 * `chat_activity_snapshot` JSON envelope. A ready terminal takes priority over
 * any retained snapshot, so activity can never obscure completion. A code-5
 * probe does not consume activity; a successful code-6 sized read does. */
int32_t neoth_companion_operation_poll_v2(neoth_companion_operation *operation,
    uint8_t *out, size_t out_len, size_t *required_len);
void neoth_companion_operation_cancel(neoth_companion_operation *operation);
/* Optional paired v3 entrypoints: explicit stream negotiation, never a resend.
 * poll_v3 adds code 7: an absolute chat_stream_snapshot preview (10 KiB text).
 * Revisions may skip because snapshots coalesce; replace instead of append.
 * A confirmed terminal supersedes previews; codes 0..6 retain v2 meanings. */
neoth_companion_operation *neoth_companion_chat_start_v3(
    neoth_companion_bridge *bridge, const uint8_t *descriptor_json,
    size_t descriptor_json_len, const uint8_t *device_id, size_t device_id_len,
    const uint8_t *message, size_t message_len, uint8_t request_tool_activity);
int32_t neoth_companion_operation_poll_v3(neoth_companion_operation *operation,
    uint8_t *out, size_t out_len, size_t *required_len);
void neoth_companion_operation_free(neoth_companion_operation *operation);

#ifdef __cplusplus
}
#endif
#endif
