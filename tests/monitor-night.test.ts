// SPDX-License-Identifier: AGPL-3.0-only
// AEG-008 / AEG-T024: activity in the night window (default 00:00–06:00, the user's timezone) raises an alert,
// once per session per night (2026-10-29).
import { describe, test, expect } from "bun:test";
import { nightOf, NightWatch } from "../src/monitor/night";

const IST = { enabled: true, start_hour: 0, end_hour: 6, timezone: "Asia/Kolkata" };

describe("night window", () => {
  test("inside and outside the window, in the configured timezone", () => {
    expect(nightOf("2026-10-28T20:44:00Z", IST)).toBe("2026-10-29");   // 02:14 IST
    expect(nightOf("2026-10-29T00:29:00Z", IST)).toBe("2026-10-29");   // 05:59 IST
    expect(nightOf("2026-10-29T00:30:00Z", IST)).toBe(null);           // 06:00 IST
    expect(nightOf("2026-10-28T18:29:00Z", IST)).toBe(null);           // 23:59 IST
    expect(nightOf("2026-10-28T20:44:00Z", { ...IST, timezone: "Europe/London" })).toBe(null); // 20:44 in London
  });

  test("a window across midnight (22:00–06:00) belongs to the night it started", () => {
    const late = { ...IST, start_hour: 22 };
    expect(nightOf("2026-10-28T17:00:00Z", late)).toBe("2026-10-28");  // 22:30 IST on the 28th
    expect(nightOf("2026-10-28T21:00:00Z", late)).toBe("2026-10-28");  // 02:30 IST on the 29th, same night
    expect(nightOf("2026-10-28T12:00:00Z", late)).toBe(null);          // 17:30 IST
  });

  test("off, or a bad timezone or hours, means no alert, never a crash", () => {
    expect(nightOf("2026-10-28T20:44:00Z", { ...IST, enabled: false })).toBe(null);
    expect(nightOf("2026-10-28T20:44:00Z", { ...IST, timezone: "Mars/Olympus" })).toBe(null);
    expect(nightOf("2026-10-28T20:44:00Z", { ...IST, start_hour: 6, end_hour: 6 })).toBe(null);
    expect(nightOf("not a date", IST)).toBe(null);
  });
});

describe("night watch", () => {
  test("one alert per session per night, saying whether a person typed lately", () => {
    const w = new NightWatch();
    const now = Date.parse("2026-10-28T20:44:00Z");
    const a = w.check("S1", "2026-10-28T20:44:00Z", IST, undefined, now);
    expect(a?.message).toContain("02:14");
    expect(a?.message).toContain("no user input seen");
    expect(w.check("S1", "2026-10-28T21:30:00Z", IST, undefined, now)).toBe(null);           // same night: no second alert
    const b = w.check("S2", "2026-10-28T20:50:00Z", IST, now - 3 * 60_000, now);
    expect(b?.message).toContain("last user input 3 min ago");
    expect(w.check("S1", "2026-10-29T20:44:00Z", IST, undefined, now)).not.toBe(null);       // the next night: again
    expect(w.check("S3", "2026-10-29T06:00:00Z", IST, undefined, now)).toBe(null);           // 11:30 IST: day
  });
});
