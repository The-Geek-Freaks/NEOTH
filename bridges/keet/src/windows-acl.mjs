import process from '#process'
import subprocess from '#subprocess'

import b4a from 'b4a'

const ACL_SCRIPT = `$ErrorActionPreference = 'Stop'
function Protect-PrivatePath([string]$target, [bool]$isDirectory) {
  if ([string]::IsNullOrWhiteSpace($target)) { throw 'missing private path' }
  if ($isDirectory) {
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $before = [System.IO.Directory]::GetAccessControl($target)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  } else {
    $security = New-Object System.Security.AccessControl.FileSecurity
    $before = [System.IO.File]::GetAccessControl($target)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
  }
  $ownerSid = $before.GetOwner([System.Security.Principal.SecurityIdentifier])
  $security.SetAccessRuleProtection($true, $false)
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $ownerSid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    $inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  $security.AddAccessRule($rule)
  if ($isDirectory) {
    [System.IO.Directory]::SetAccessControl($target, $security)
    $current = [System.IO.Directory]::GetAccessControl($target)
  } else {
    [System.IO.File]::SetAccessControl($target, $security)
    $current = [System.IO.File]::GetAccessControl($target)
  }
  $owner = $current.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  $rules = @($current.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  $expectedRights = [System.Security.AccessControl.FileSystemRights]::FullControl
  $valid = $current.AreAccessRulesProtected -and $owner -eq $ownerSid.Value -and $rules.Count -eq 1
  if ($valid) {
    $actual = $rules[0]
    $valid = $actual.IdentityReference.Value -eq $ownerSid.Value -and
      $actual.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      (($actual.FileSystemRights -band $expectedRights) -eq $expectedRights) -and
      $actual.InheritanceFlags -eq $inheritance -and
      $actual.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None
  }
  if (-not $valid) { throw 'private ACL verification failed' }
}
foreach ($line in $env:NEOTH_PRIVATE_PATHS.Split(';')) {
  if ($line.Length -lt 3 -or $line[1] -ne ':') { throw 'invalid private ACL input' }
  $target = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($line.Substring(2)))
  if ($line[0] -eq 'D') { Protect-PrivatePath $target $true }
  elseif ($line[0] -eq 'F') { Protect-PrivatePath $target $false }
  else { throw 'invalid private path kind' }
}
`

const ENCODED_ACL_SCRIPT = encodePowerShell(ACL_SCRIPT)

export function securePrivatePath (
  target,
  { directory, platform = globalThis.Bare?.platform || process.platform, spawnSync = subprocess.spawnSync } = {}
) {
  return securePrivatePaths([{ target, directory }], { platform, spawnSync })
}

export function securePrivatePaths (
  entries,
  { platform = globalThis.Bare?.platform || process.platform, spawnSync = subprocess.spawnSync } = {}
) {
  if (platform !== 'win32') return
  if (!Array.isArray(entries) || entries.length === 0) throw new Error('at least one private ACL path is required')
  for (const { target, directory } of entries) {
    if (typeof target !== 'string' || target.length === 0 || target.includes('\0')) throw new Error('invalid private ACL path')
    if (directory !== true && directory !== false) throw new Error('private ACL path kind is required')
  }
  const encoded = entries.map(({ target, directory }) => {
    return `${directory ? 'D' : 'F'}:${b4a.toString(b4a.from(target), 'base64')}`
  })
  for (const chunk of environmentChunks(encoded, 16 * 1024)) {
    const result = spawnSync('powershell.exe', [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-EncodedCommand',
      ENCODED_ACL_SCRIPT
    ], {
      env: { ...process.env, NEOTH_PRIVATE_PATHS: chunk.join(';') },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      maxBuffer: 64 * 1024
    })

    if (result.error) throw new Error(`could not apply private Windows ACL: ${result.error.message}`)
    if (result.status !== 0) {
      const detail = outputText(result.stderr) || outputText(result.stdout) || `exit ${result.status}`
      throw new Error(`private Windows ACL setup failed: ${detail.slice(0, 1024)}`)
    }
  }
}

function environmentChunks (values, limit) {
  const chunks = []
  let current = []
  let length = 0
  for (const value of values) {
    if (value.length > limit) throw new Error('private ACL path exceeds the Windows environment safety limit')
    const next = length + (current.length > 0 ? 1 : 0) + value.length
    if (next > limit) {
      chunks.push(current)
      current = []
      length = 0
    }
    current.push(value)
    length += (current.length > 1 ? 1 : 0) + value.length
  }
  if (current.length > 0) chunks.push(current)
  return chunks
}

function encodePowerShell (source) {
  const bytes = new Uint8Array(source.length * 2)
  for (let index = 0; index < source.length; index++) {
    const code = source.charCodeAt(index)
    bytes[index * 2] = code & 0xff
    bytes[index * 2 + 1] = code >>> 8
  }
  return b4a.toString(bytes, 'base64')
}

function outputText (value) {
  if (!value || value.byteLength === 0) return ''
  return b4a.toString(value).replace(/[\r\n\t ]+/g, ' ').trim()
}
