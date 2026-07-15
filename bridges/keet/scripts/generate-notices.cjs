'use strict'

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const { createRequire } = require('module')

const bridgeRoot = path.resolve(__dirname, '..')
const repositoryRoot = path.resolve(bridgeRoot, '..', '..')
const markerStart = '<!-- BEGIN GENERATED: KEET DESKTOP RUNTIME LICENSES -->'
const markerEnd = '<!-- END GENERATED: KEET DESKTOP RUNTIME LICENSES -->'
const desktopBuildRuntimes = new Set([
  'bare-build-darwin-arm64',
  'bare-build-darwin-x64',
  'bare-build-linux-arm64',
  'bare-build-linux-x64',
  'bare-build-win32-arm64',
  'bare-build-win32-x64'
])
const licensePattern = /^(?:licen[cs]e|copying|notice)(?:[._-].*)?$/i

const args = process.argv.slice(2)
const mode = args.shift()
const target = path.resolve(args.shift() || path.join(repositoryRoot, 'THIRD_PARTY_LICENSES'))
if ((mode !== '--write' && mode !== '--check') || args.length !== 0) {
  fail('usage: node scripts/generate-notices.cjs --write|--check [THIRD_PARTY_LICENSES]')
}

const generated = generateSection()
const current = fs.readFileSync(target, 'utf8').replace(/\r\n/g, '\n')
const next = replaceGeneratedSection(current, generated)
if (mode === '--check') {
  if (next !== current) fail(`${path.relative(repositoryRoot, target)} has stale Keet runtime notices`)
  console.log(`Keet runtime notices are current in ${path.relative(repositoryRoot, target)}`)
} else {
  fs.writeFileSync(target, next, 'utf8')
  console.log(`Updated ${path.relative(repositoryRoot, target)}`)
}

function generateSection () {
  const rootPackage = readJson(path.join(bridgeRoot, 'package.json'))
  const initial = [
    ...Object.keys(rootPackage.dependencies || {}),
    ...desktopBuildRuntimes
  ]
  const queue = initial.map(name => resolvePackage(name, bridgeRoot))
  const packages = new Map()
  while (queue.length > 0) {
    const directory = queue.shift()
    const manifestPath = path.join(directory, 'package.json')
    const manifest = readJson(manifestPath)
    const key = `${manifest.name}@${manifest.version}:${fs.realpathSync.native(directory)}`
    if (packages.has(key)) continue
    packages.set(key, { directory, manifest })

    const dependencies = {
      ...(manifest.dependencies || {}),
      ...(manifest.optionalDependencies || {})
    }
    for (const name of Object.keys(dependencies).sort()) {
      try {
        queue.push(resolvePackage(name, directory))
      } catch (error) {
        if (!(manifest.optionalDependencies || {})[name]) throw error
      }
    }
  }

  const records = [...packages.values()].sort((left, right) => packageId(left).localeCompare(packageId(right)))
  const groups = new Map()
  const missing = []
  for (const record of records) {
    const files = fs.readdirSync(record.directory, { withFileTypes: true })
      .filter(entry => entry.isFile() && licensePattern.test(entry.name))
      .map(entry => entry.name)
      .sort((left, right) => left.localeCompare(right))
    if (files.length === 0) {
      missing.push(record)
      continue
    }
    for (const name of files) {
      const content = normalizeNoticeText(fs.readFileSync(path.join(record.directory, name), 'utf8'))
      addGroup(groups, content, record, name, false)
    }
  }

  for (const record of missing) {
    const declared = normalizeLicense(record.manifest.license)
    if (declared === 'Apache-2.0') {
      const content = normalizeNoticeText(fs.readFileSync(path.join(repositoryRoot, 'LICENSE-APACHE'), 'utf8'))
      addGroup(groups, content, record, 'declared Apache-2.0 fallback', true)
    } else if (declared === 'ISC' && record.manifest.name === 'noise-curve-ed') {
      addGroup(groups, `${iscFallback()}\n`, record, 'declared ISC fallback', true)
    } else {
      fail(`${packageId(record)} declares ${declared || 'no license'} but ships no license text`)
    }
  }

  const output = []
  output.push(markerStart)
  output.push('')
  output.push('## Embedded Keet/Pear desktop companion dependencies')
  output.push('')
  output.push(
    `Generated from the frozen \`bridges/keet\` dependency graph. The ${records.length} ` +
    'entries cover the production JavaScript closure plus the Bare runtime binaries used by ' +
    'the supported macOS, Linux and Windows x64/ARM64 standalone builds. Byte-identical ' +
    'license and NOTICE texts are grouped once; every covered package and exact version is ' +
    'listed below. Regenerate with `node bridges/keet/scripts/generate-notices.cjs --write`.'
  )
  output.push('')
  output.push(
    '**Modification notice:** NEOTH modifies the Apache-2.0 ' +
    '`bare-build-win32-x64@1.0.2` and `bare-build-win32-arm64@1.0.2` portable ' +
    'runtime executables during standalone assembly. The fail-closed patch in ' +
    '`bridges/keet/scripts/windows-runtime.cjs` changes one guarded console branch ' +
    'per architecture so redirected CLI stdout/stderr remain available instead of ' +
    'being reopened to `NUL`. No other runtime bytes are changed.'
  )
  output.push('')

  const orderedGroups = [...groups.values()].sort((left, right) => {
    const leftId = [...left.packages].sort()[0]
    const rightId = [...right.packages].sort()[0]
    return leftId.localeCompare(rightId) || left.hash.localeCompare(right.hash)
  })
  for (const group of orderedGroups) {
    output.push(`### License/NOTICE group \`${group.hash.slice(0, 12)}\``)
    output.push('')
    output.push('Covered packages:')
    output.push('')
    for (const id of [...group.packages].sort()) {
      const details = group.details.get(id)
      const fallback = details.fallback ? '; upstream package omitted a standalone license file' : ''
      output.push(`- \`${id}\` — declared \`${details.license}\`; ${details.files.join(', ')}${fallback}; ${details.source}`)
    }
    output.push('')
    output.push('```text')
    output.push(group.content.trimEnd())
    output.push('```')
    output.push('')
  }
  output.push(markerEnd)
  output.push('')
  return output.join('\n')
}

function addGroup (groups, content, record, file, fallback) {
  const hash = crypto.createHash('sha256').update(content).digest('hex')
  let group = groups.get(hash)
  if (!group) {
    group = { hash, content, packages: new Set(), details: new Map() }
    groups.set(hash, group)
  }
  const id = packageId(record)
  group.packages.add(id)
  const current = group.details.get(id) || {
    license: normalizeLicense(record.manifest.license) || 'UNDECLARED',
    files: [],
    fallback: false,
    source: sourceUrl(record.manifest)
  }
  current.files.push(file)
  current.fallback = current.fallback || fallback
  group.details.set(id, current)
}

function normalizeNoticeText (content) {
  return content
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map(line => line.trimEnd())
    .join('\n')
    .trimEnd() + '\n'
}

function resolvePackage (name, fromDirectory) {
  const resolver = createRequire(path.join(fromDirectory, 'package.json'))
  try {
    return fs.realpathSync.native(path.dirname(resolver.resolve(`${name}/package.json`)))
  } catch (_) {
    let cursor = path.dirname(resolver.resolve(name))
    while (cursor !== path.dirname(cursor)) {
      const manifest = path.join(cursor, 'package.json')
      if (fs.existsSync(manifest) && readJson(manifest).name === name) return fs.realpathSync.native(cursor)
      cursor = path.dirname(cursor)
    }
    throw new Error(`cannot resolve package metadata for ${name} from ${fromDirectory}`)
  }
}

function sourceUrl (manifest) {
  const raw = typeof manifest.repository === 'string'
    ? manifest.repository
    : manifest.repository && manifest.repository.url
  if (raw) return raw.replace(/^git\+/, '').replace(/\.git$/, '')
  if (manifest.homepage) return manifest.homepage.replace(/#readme$/, '')
  return `https://www.npmjs.com/package/${encodeURIComponent(manifest.name)}`
}

function normalizeLicense (license) {
  if (typeof license === 'string') return license
  if (Array.isArray(license)) return license.map(normalizeLicense).filter(Boolean).join(' OR ')
  if (license && typeof license.type === 'string') return license.type
  return ''
}

function packageId (record) {
  return `${record.manifest.name}@${record.manifest.version}`
}

function replaceGeneratedSection (current, section) {
  const start = current.indexOf(markerStart)
  const end = current.indexOf(markerEnd)
  if (start === -1 && end === -1) return `${current.trimEnd()}\n\n---\n\n${section}`
  if (start === -1 || end === -1 || end < start) fail('malformed generated Keet notice markers')
  const after = end + markerEnd.length
  return `${current.slice(0, start).trimEnd()}\n\n${section}${current.slice(after).replace(/^\s*/, '')}`
}

function iscFallback () {
  return `ISC License

Copyright (c) chm-diederichs/noise-curve-ed contributors

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
USE OR PERFORMANCE OF THIS SOFTWARE.`
}

function readJson (file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

function fail (message) {
  console.error(`generate-notices: ${message}`)
  process.exit(1)
}
