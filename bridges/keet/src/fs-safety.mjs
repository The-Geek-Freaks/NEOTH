import fs from '#fs'

import b4a from 'b4a'

export function writeAllSync (handle, value, writeSync = defaultWriteSync) {
  const bytes = typeof value === 'string' ? b4a.from(value) : value
  if (!(bytes instanceof Uint8Array)) throw new TypeError('durable write value must be a string or Uint8Array')

  let offset = 0
  while (offset < bytes.byteLength) {
    const written = writeSync(handle, bytes, offset, bytes.byteLength - offset, null)
    if (!Number.isSafeInteger(written) || written <= 0 || written > bytes.byteLength - offset) {
      throw new Error('durable file write did not make valid forward progress')
    }
    offset += written
  }
}

export function fsyncDirectorySync (
  directory,
  {
    openSync = (target, flags) => fs.openSync(target, flags),
    fsyncSync = (handle) => fs.fsyncSync(handle),
    closeSync = (handle) => fs.closeSync(handle)
  } = {}
) {
  let handle
  try {
    handle = openSync(directory, 'r')
  } catch (error) {
    if (directoryFsyncUnsupported(error)) return false
    throw error
  }
  let supported = true
  let failure = null
  try {
    fsyncSync(handle)
  } catch (error) {
    if (directoryFsyncUnsupported(error)) supported = false
    else failure = error
  }
  try { closeSync(handle) } catch (error) {
    failure = failure ? new AggregateError([failure, error], 'directory fsync and close both failed') : error
  }
  if (failure) throw failure
  return supported
}

function defaultWriteSync (handle, bytes, offset, length, position) {
  return fs.writeSync(handle, bytes, offset, length, position)
}

function directoryFsyncUnsupported (error) {
  return ['EACCES', 'EINVAL', 'EISDIR', 'ENOSYS', 'ENOTSUP', 'EPERM'].includes(error?.code)
}
