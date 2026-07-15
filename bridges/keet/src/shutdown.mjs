export function createShutdownHandler ({ server, service, storageLock = null, onError, exit }) {
  let shutdownPromise = null
  let fatalReason = null
  return function shutdown (reason = null) {
    if (reason && !fatalReason) fatalReason = reason
    if (shutdownPromise) return shutdownPromise
    shutdownPromise = closeRuntime(server, service, storageLock)
    void shutdownPromise.then(
      () => {
        if (fatalReason) {
          try { onError(fatalReason) } finally { exit(1) }
        } else {
          exit(0)
        }
      },
      (error) => {
        const reported = fatalReason
          ? new AggregateError([fatalReason, error], 'fatal bridge failure and shutdown failure')
          : error
        try { onError(reported) } finally { exit(1) }
      }
    )
    return shutdownPromise
  }
}

export async function closeRuntime (server, service, storageLock = null) {
  const errors = []
  try { await server.close() } catch (error) { errors.push(error) }
  try { await service.close() } catch (error) { errors.push(error) }
  if (storageLock) {
    try { await storageLock.close() } catch (error) { errors.push(error) }
  }
  if (errors.length > 0) throw new AggregateError(errors, 'bridge runtime shutdown failed')
}
