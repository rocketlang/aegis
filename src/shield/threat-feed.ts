// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// AEGIS Shield — LakshmanRekha Live Threat Feed
// @rule:KAV-082 Live threat feed — LakshmanRekha probe.failed events update shield-rules at runtime
// probe.failed events from LakshmanRekha carry payload samples that reveal new injection vectors.
// This module ingests those payloads, extracts detectable patterns, and merges them into the
// injection detector at check time — without requiring a restart or file edit.

const FEED_MAX = 500;

export interface ThreatFeedEntry {
  probe_id: string;
  pattern: string;          // regex or substring added to injection detector
  source: "lakshmanrekha";
  added_at: string;
  rule_ref: "KAV-082";
}

// In-memory feed store — capped at FEED_MAX entries (oldest evicted on overflow)
const feedStore: ThreatFeedEntry[] = [];

/**
 * Ingest a probe.failed event from LakshmanRekha.
 * Extracts a detectable pattern from the payload and appends it to the feed store.
 * Pattern extraction strategy: use the first 120 printable chars of the payload,
 * escaped for use as a literal regex substring.
 * @rule:KAV-082
 */
export function ingestProbeFailure(probeId: string, payload: string): ThreatFeedEntry {
  // Extract a stable, regex-safe substring from the probe payload
  const raw = payload.replace(/[\r\n]+/g, " ").trim().slice(0, 120);
  // Escape special regex chars so the extracted string works as a literal match
  const escaped = raw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  const entry: ThreatFeedEntry = {
    probe_id: probeId,
    pattern: escaped,
    source: "lakshmanrekha",
    added_at: new Date().toISOString(),
    rule_ref: "KAV-082",
  };

  feedStore.push(entry);
  // Evict oldest entries if cap is exceeded
  if (feedStore.length > FEED_MAX) {
    feedStore.splice(0, feedStore.length - FEED_MAX);
  }

  return entry;
}

/**
 * Returns all current live threat patterns for merging into the injection detector.
 * @rule:KAV-082
 */
export function getFeedPatterns(): string[] {
  return feedStore.map((e) => e.pattern);
}

/**
 * Clear all feed entries (for testing only).
 */
export function clearFeed(): void {
  feedStore.splice(0, feedStore.length);
}
