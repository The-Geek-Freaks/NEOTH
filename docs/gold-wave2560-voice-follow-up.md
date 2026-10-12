# Optional voice follow-up window

The existing conversation owner accepts `media.conversation_follow_up_secs` in an accepted `freedom.yaml` snapshot. Omit it or set it to null to retain continuous listening. Explicit values must be whole seconds between 1 and 300. Zero is invalid. Invalid snapshots are rejected, and the conversation session also validates before opening the microphone.

```yaml
media:
  conversation_follow_up_secs: 7
```

The window begins only after the current authorized text turn has completely settled and its spoken response has finished playback, with no queued or active audio. Failed turns and responses without observed playback never create a playback-complete claim. The existing Listening state is emitted when the window arms. Qualified new speech or an explicit barge-in invalidates that response generation; short noise and repeated completion notifications do not extend its deadline.

At the deadline, already queued capture observations at or before the cutoff are processed first. A fixed snapshot of the bounded queue checks for eligible input and terminal events behind late frames. Fresh noise cannot make that scan grow. This boundary is the existing relay's monotonic observation time, not physical microphone callback time or a guarantee about audio still upstream of the relay.

Autonomous expiry uses the existing shutdown sequence: cancel capture/response, settle stage workers, settle dropped text turns, join the supervisor, drain cleanup, and release the session's audio permit. A one-shot capture terminal witness is written before a possibly blocked PCM-queue send, then read only after the relay has joined. Capture failure and cancellation therefore survive a full queue and expiry races. The final event waits for queue capacity: completed expiry projects the existing Stopped state; cancellation and failure retain their existing terminal projections. Cleanup failure remains the primary error. Any abnormal A2 task termination also publishes Failed through this same post-cleanup path, so the owner pump does not remain on a stale Listening state when no further RPC arrives.

This is an explicit opt-in configuration of the desktop conversation owner. It adds no wakeword, microphone permission, model/provider authorization, mobile GUI, Slint edit, or remote device activation. It implements a slice of JM-EX-02; physical device acceptance and the wider Jarvis adoption items remain open.

Validation scope: sixteen authored regression cases cover config, ordering, generations, speech threshold, idle audio, deadline FIFO, bounded noise, cancellation, blocked terminal transport, delayed terminal settlement and event backpressure. One is portable; fifteen require live-audio. These cases are registered in the existing hosted W186 lane. They do not substitute for an actual hardware conversation or a complete synthetic run_a2_session integration harness.
