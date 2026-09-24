import { Notice, Plugin, TFile } from "obsidian";

const PLUGIN_ID = "neoth-archive-bridge";
const PLUGIN_VERSION = "0.1.1";
const DISABLED_STATUS = "NEOTH Archive Bridge: not paired (sync disabled)";

/**
 * A deliberately read-only Obsidian companion.  This artifact does not create
 * a pairing, change a note, register a file watcher, or contact a service.
 * A future native NEOTH owner must issue and validate pairing before sync can
 * be enabled; until then, the only command inspects local NEOTH session notes.
 */
export default class NeothArchiveBridge extends Plugin {
  private statusItem?: { setText(text: string): void; remove(): void };

  async onload(): Promise<void> {
    this.statusItem = this.addStatusBarItem();
    this.statusItem.setText(DISABLED_STATUS);
    this.addCommand({
      id: "inspect-local-archive-notes",
      name: "Inspect local NEOTH session notes",
      callback: () => this.inspectLocalArchiveNotes(),
    });
  }

  onunload(): void {
    this.statusItem?.remove();
    this.statusItem = undefined;
  }

  private inspectLocalArchiveNotes(): void {
    const sessionNotes = this.app.vault
      .getMarkdownFiles()
      .filter((file) => isNeothSessionNote(file));
    new Notice(
      `${PLUGIN_ID} ${PLUGIN_VERSION}: ${sessionNotes.length} local NEOTH session note(s); pairing and sync remain disabled.`,
    );
  }
}

function isNeothSessionNote(file: TFile): boolean {
  return file.path.startsWith("NEOTH-sessions/");
}
