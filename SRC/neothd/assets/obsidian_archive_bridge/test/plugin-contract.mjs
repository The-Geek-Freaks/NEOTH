import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Module from "node:module";

const root = path.resolve(import.meta.dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
const source = fs.readFileSync(path.join(root, "src", "main.ts"), "utf8");

test("manifest pins the loadable Obsidian plugin identity", () => {
  assert.equal(manifest.id, "neoth-archive-bridge");
  assert.equal(manifest.version, "0.1.0");
  assert.equal(manifest.minAppVersion, "1.5.0");
  assert.equal(manifest.isDesktopOnly, false);
});

test("source keeps pairing and sync disabled and has no network or ingest path", () => {
  for (const forbidden of ["fetch(", "requestUrl", "XMLHttpRequest", "WebSocket", "on(\"modify\"", "vault.modify", "vault.create"]) {
    assert.equal(source.includes(forbidden), false, `forbidden source capability: ${forbidden}`);
  }
  assert.match(source, /not paired \(sync disabled\)/);
  assert.match(source, /Inspect local NEOTH session notes/);
  assert.match(source, /NEOTH-sessions\//);
  assert.match(source, /onunload/);
});

test("built bundle exports an Obsidian plugin and unload cleans the status item", async () => {
  const bundle = path.join(root, "main.js");
  assert.equal(fs.existsSync(bundle), true, "hosted build must create main.js");

  const originalLoad = Module._load;
  const notices = [];
  class FakePlugin {
    constructor(app) {
      this.app = app;
      this.commands = [];
    }
    addCommand(command) {
      this.commands.push(command);
    }
    addStatusBarItem() {
      return {
        setText: (text) => { this.statusText = text; },
        remove: () => { this.statusRemoved = true; },
      };
    }
  }
  class FakeNotice {
    constructor(message) {
      notices.push(message);
    }
  }
  Module._load = (request, parent, isMain) => request === "obsidian"
    ? { Plugin: FakePlugin, Notice: FakeNotice }
    : originalLoad(request, parent, isMain);
  try {
    const loaded = await import(`${bundle}?build=${Date.now()}`);
    const PluginClass = loaded.default.default ?? loaded.default;
    const instance = new PluginClass({ vault: { getMarkdownFiles: () => [{ path: "Daily/2026-09-24.md" }, { path: "NEOTH-sessions/2026-09-24.md" }, { path: "other.md" }] } });
    await instance.onload();
    assert.equal(instance.statusText, "NEOTH Archive Bridge: not paired (sync disabled)");
    assert.equal(instance.commands.length, 1);
    instance.commands[0].callback();
    assert.match(notices[0], /1 local NEOTH session note/);
    instance.onunload();
    assert.equal(instance.statusRemoved, true);
  } finally {
    Module._load = originalLoad;
  }
});
