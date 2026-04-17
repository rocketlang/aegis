// AEGIS Monitor — File Watcher (Polling-Only, Active-Session-Focused)
// Watches ONLY recently-modified JSONL files — skips historical sessions

import { existsSync, readdirSync, statSync, readFileSync } from "fs";
import { join } from "path";
import { parseLine } from "./parser";
import type { UsageRecord } from "../core/types";

export type UsageCallback = (record: UsageRecord, projectPath: string) => void;
export type UserActivityCallback = (session_id: string) => void;

interface FileState {
  path: string;
  offset: number;
  mtime: number;
}

// Only track files modified within this window (default: 24 hours)
const ACTIVE_WINDOW_MS = 24 * 60 * 60 * 1000;
// Only scan for new files every N polls
const DIR_RESCAN_INTERVAL = 10;

export class SessionWatcher {
  private files = new Map<string, FileState>();
  private onUsage: UsageCallback;
  private onUserActivity: UserActivityCallback;
  private pollInterval: number;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private watchPaths: string[] = [];
  private pollCount = 0;

  constructor(onUsage: UsageCallback, onUserActivity: UserActivityCallback, pollInterval: number = 2000) {
    this.onUsage = onUsage;
    this.onUserActivity = onUserActivity;
    this.pollInterval = pollInterval;
  }

  start(watchPaths: string[]): void {
    this.watchPaths = watchPaths;

    // Initial scan — find RECENTLY-ACTIVE files only
    this.scanForActiveFiles();

    // Poll loop: read new data from tracked files, rescan directory periodically
    this.pollTimer = setInterval(() => {
      this.pollCount++;
      this.pollTrackedFiles();
      // Every Nth poll, check for new files
      if (this.pollCount % DIR_RESCAN_INTERVAL === 0) {
        this.scanForActiveFiles();
      }
    }, this.pollInterval);
  }

  stop(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
  }

  private scanForActiveFiles(): void {
    const cutoff = Date.now() - ACTIVE_WINDOW_MS;
    for (const base of this.watchPaths) {
      if (!existsSync(base)) continue;
      this.scanDirectoryShallow(base, cutoff);
    }
  }

  private scanDirectoryShallow(dir: string, cutoff: number, depth: number = 0): void {
    if (depth > 3) return;
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = join(dir, entry.name);
        try {
          if (entry.isDirectory()) {
            const dstat = statSync(full);
            // Skip entire directory if nothing modified recently
            if (dstat.mtimeMs < cutoff) continue;
            this.scanDirectoryShallow(full, cutoff, depth + 1);
          } else if (entry.name.endsWith(".jsonl")) {
            const fstat = statSync(full);
            if (fstat.mtimeMs >= cutoff) {
              this.registerFile(full, fstat.size, fstat.mtimeMs);
            }
          }
        } catch { /* file vanished, permission denied */ }
      }
    } catch { /* */ }
  }

  private registerFile(path: string, size: number, mtime: number): void {
    if (this.files.has(path)) return;
    // Start at current end — don't re-read historical data
    this.files.set(path, { path, offset: size, mtime });
  }

  private pollTrackedFiles(): void {
    const toRemove: string[] = [];
    for (const [path, state] of this.files) {
      try {
        const stat = statSync(path);
        if (stat.size > state.offset) {
          this.processNewData(path, state, stat.size);
        }
        // Unregister files that go stale (no activity for 1 hour)
        if (Date.now() - stat.mtimeMs > 60 * 60 * 1000) {
          toRemove.push(path);
        }
      } catch {
        toRemove.push(path);
      }
    }
    for (const path of toRemove) {
      this.files.delete(path);
    }
  }

  private processNewData(path: string, state: FileState, newSize: number): void {
    try {
      const buf = readFileSync(path);
      const newData = buf.subarray(state.offset).toString("utf-8");
      state.offset = newSize;

      const projectPath = this.extractProjectPath(path);
      const lines = newData.split("\n");

      for (const line of lines) {
        if (!line.trim()) continue;
        const parsed = parseLine(line, projectPath);
        if (parsed.usage) {
          this.onUsage(parsed.usage, projectPath);
        }
        if (parsed.is_user_message && parsed.session_id) {
          this.onUserActivity(parsed.session_id);
        }
      }
    } catch { /* */ }
  }

  private extractProjectPath(filePath: string): string {
    // Claude Code: /root/.claude/projects/-root-xxx/session.jsonl → /root/xxx
    const claude = filePath.match(/\.claude\/projects\/([^/]+)\//);
    if (claude) return claude[1].replace(/^-/, "/").replace(/-/g, "/");
    // Codex: /root/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl → return full file path
    // (cwd is inside the session_meta, not the path)
    if (filePath.includes("/.codex/sessions/")) return filePath;
    return "unknown";
  }

  getWatchedFileCount(): number {
    return this.files.size;
  }
}
