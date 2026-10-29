// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Monitor — night-time activity (AEG-T024)
// @rule:AEG-008 Night-time activity (00:00-06:00 user timezone) must trigger an alert
// One alert per session per night. The alert says whether a person typed lately, so "working late" and
// "running on its own at 02:00" read differently. A bad timezone or window turns the check off quietly
// (the monitor must not crash on a config typo); `aegis doctor`-style checks can report it.

export interface NightConfig {
  enabled: boolean;
  start_hour: number;   // 0-23, local to timezone
  end_hour: number;     // 0-23, exclusive; a window may run across midnight (22 -> 6)
  timezone: string;     // IANA name; "" = the box's own timezone
}

export const DEFAULT_NIGHT: NightConfig = { enabled: true, start_hour: 0, end_hour: 6, timezone: "" };

// Local date and hour of an instant in a timezone; null when the timezone is not one Intl knows.
function localParts(ms: number, timezone: string): { date: string; hour: number; minute: number } | null {
  try {
    const f = new Intl.DateTimeFormat("en-CA", { timeZone: timezone || undefined, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
    const p = Object.fromEntries(f.formatToParts(new Date(ms)).map((x) => [x.type, x.value]));
    return { date: `${p.year}-${p.month}-${p.day}`, hour: Number(p.hour), minute: Number(p.minute) };
  } catch { return null; }
}

const validHour = (h: unknown): h is number => typeof h === "number" && Number.isInteger(h) && h >= 0 && h <= 23;

// The night an instant falls in, named by the local date the window began on; null outside the window.
export function nightOf(timestamp: string, cfg: Partial<NightConfig> = {}): string | null {
  const c = { ...DEFAULT_NIGHT, ...cfg };
  if (!c.enabled || !validHour(c.start_hour) || !validHour(c.end_hour) || c.start_hour === c.end_hour) return null;
  const ms = Date.parse(timestamp);
  if (!Number.isFinite(ms)) return null;
  const here = localParts(ms, c.timezone);
  if (!here) return null;
  const across = c.start_hour > c.end_hour;
  const inside = across ? here.hour >= c.start_hour || here.hour < c.end_hour : here.hour >= c.start_hour && here.hour < c.end_hour;
  if (!inside) return null;
  // After midnight in a window that began the evening before: the night is named by yesterday's date.
  if (across && here.hour < c.end_hour) return localParts(ms - 86_400_000, c.timezone)?.date ?? null;
  return here.date;
}

export interface NightAlert { night: string; message: string }

export class NightWatch {
  private alerted = new Set<string>();

  check(session_id: string, timestamp: string, cfg: Partial<NightConfig>, lastUserInputMs: number | undefined, now = Date.now()): NightAlert | null {
    const night = nightOf(timestamp, cfg);
    if (!night) return null;
    const key = `${session_id}|${night}`;
    if (this.alerted.has(key)) return null;
    this.alerted.add(key);
    if (this.alerted.size > 5000) this.alerted.clear();   // a bound, not a schedule: worst case one repeat alert
    const c = { ...DEFAULT_NIGHT, ...cfg };
    const t = localParts(Date.parse(timestamp), c.timezone)!;
    const hhmm = `${String(t.hour).padStart(2, "0")}:${String(t.minute).padStart(2, "0")}`;
    const tz = c.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone;
    const window = `${String(c.start_hour).padStart(2, "0")}:00–${String(c.end_hour).padStart(2, "0")}:00 ${tz}`;
    const who = lastUserInputMs === undefined ? "no user input seen" : `last user input ${Math.round((now - lastUserInputMs) / 60_000)} min ago`;
    return { night, message: `Session ${session_id.slice(0, 8)} active at ${hhmm} (night window ${window}); ${who}` };
  }
}
