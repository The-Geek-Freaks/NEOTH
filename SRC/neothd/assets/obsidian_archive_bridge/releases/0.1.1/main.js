"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => NeothArchiveBridge
});
module.exports = __toCommonJS(main_exports);
var import_obsidian = require("obsidian");
var PLUGIN_ID = "neoth-archive-bridge";
var PLUGIN_VERSION = "0.1.1";
var DISABLED_STATUS = "NEOTH Archive Bridge: not paired (sync disabled)";
var NeothArchiveBridge = class extends import_obsidian.Plugin {
  async onload() {
    this.statusItem = this.addStatusBarItem();
    this.statusItem.setText(DISABLED_STATUS);
    this.addCommand({
      id: "inspect-local-archive-notes",
      name: "Inspect local NEOTH session notes",
      callback: () => this.inspectLocalArchiveNotes()
    });
  }
  onunload() {
    this.statusItem?.remove();
    this.statusItem = void 0;
  }
  inspectLocalArchiveNotes() {
    const sessionNotes = this.app.vault.getMarkdownFiles().filter((file) => isNeothSessionNote(file));
    new import_obsidian.Notice(
      `${PLUGIN_ID} ${PLUGIN_VERSION}: ${sessionNotes.length} local NEOTH session note(s); pairing and sync remain disabled.`
    );
  }
};
function isNeothSessionNote(file) {
  return file.path.startsWith("NEOTH-sessions/");
}
