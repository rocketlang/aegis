// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Monitor — File Watcher (Polling-Only, Active-Session-Focused)
// Watches ONLY recently-modified JSONL files — skips historical sessions

import { existsSync, readdirSync, statSync, readFileSync, writeFileSync, renameSync } from "fs";
import { join } from "path";
import { parseLine } from "./parser";
import type { UsageRecord } from "../core/types";

export type UsageCallback = (record: UsageRecord, projectPath: string) => void;
export type UserActivityCallback = (session_id: string) => void;

interface FileState {
  path: string;
  offset: number;
  mtime: number;
  since?: number;   // read from the top, but count only lines dated from this time (ms)
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
  private startedAt = 0;
  private initialScanDone = false;
  // Where reading stopped in files let go of as idle, so a resumed session picks up from there.
  private letGo = new Map<string, number>();
  // AEG-T045: read positions saved to stateFile, so a restart resumes where the last run stopped (what was
  // written while the monitor was down is counted once, nothing twice). Without a stateFile: start at the end.
  private stateFile?: string;
  private saved = new Map<string, number>();
  private dirty = false;

  constructor(onUsage: UsageCallback, onUserActivity: UserActivityCallback, pollInterval: number = 2000, stateFile?: string) {
    this.onUsage = onUsage;
    this.onUserActivity = onUserActivity;
    this.pollInterval = pollInterval;
    this.stateFile = stateFile;
  }

  start(watchPaths: string[]): void {
    this.watchPaths = watchPaths;
    this.startedAt = Date.now();
    this.loadState();

    // Initial scan — find RECENTLY-ACTIVE files only
    this.scanForActiveFiles();
    this.initialScanDone = true;

    // Poll loop: read new data from tracked files, rescan directory periodically
    this.pollTimer = setInterval(() => {
      this.pollCount++;
      this.pollTrackedFiles();
      if (this.dirty) this.saveState();
      // Every Nth poll, check for new files
      if (this.pollCount % DIR_RESCAN_INTERVAL === 0) {
        this.scanForActiveFiles();
      }
    }, this.pollInterval);
  }

  stop(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.saveState();
  }

  private loadState(): void {
    if (!this.stateFile || !existsSync(this.stateFile)) return;
    try {
      const o = JSON.parse(readFileSync(this.stateFile, "utf-8"));
      for (const [k, v] of Object.entries(o ?? {})) if (typeof v === "number" && v >= 0) this.saved.set(k, v);
    } catch { /* unreadable: start at the end, as without a state file */ }
  }

  // Written whole to a temporary file and renamed, so a crash never leaves half a file.
  // A crash between counting a batch and saving its position can count that one batch twice.
  private saveState(): void {
    if (!this.stateFile) return;
    const o: Record<string, number> = {};
    for (const [k, v] of this.letGo) o[k] = v;
    for (const [k, st] of this.files) o[k] = st.offset;
    try {
      writeFileSync(this.stateFile + ".tmp", JSON.stringify(o));
      renameSync(this.stateFile + ".tmp", this.stateFile);
      this.dirty = false;
    } catch { /* the next poll tries again */ }
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
            // A folder's own mtime changes when a file is added, not when one grows: a session resumed in a
            // folder idle for a day would be skipped (AEG-T046). Each file's own mtime decides instead.
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
    const left = this.letGo.get(path);
    if (left !== undefined) {
      this.letGo.delete(path);
      this.files.set(path, { path, offset: left <= size ? left : size, mtime });
      return;
    }
    // There when the monitor started: resume at the saved position, if one fits; else start at the end —
    // history before the start is not ours to count.
    if (!this.initialScanDone) {
      const at = this.saved.get(path);
      this.files.set(path, { path, offset: at !== undefined && at <= size ? at : size, mtime });
      this.dirty = true;
      return;
    }
    // Found on a later rescan: it may have written for up to a rescan interval before we saw it. Read it
    // from the top and count only lines dated from the monitor's start (a resumed old session's history
    // is not counted twice).
    this.files.set(path, { path, offset: 0, mtime, since: this.startedAt });
    this.dirty = true;
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
          this.letGo.set(path, state.offset);
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
      this.dirty = true;
      const since = state.since;
      delete state.since;

      const projectPath = this.extractProjectPath(path);
      const lines = newData.split("\n");

      for (const line of lines) {
        if (!line.trim()) continue;
        if (since !== undefined) {
          const ts = Date.parse(line.match(/"timestamp"\s*:\s*"([^"]+)"/)?.[1] ?? "");
          if (!(ts >= since)) continue;   // undated or older than the start: not counted
        }
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
