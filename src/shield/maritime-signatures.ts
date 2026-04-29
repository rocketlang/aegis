// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// [EE] AEGIS Shield — Maritime Domain Injection Signatures
// Extends DEFAULT_RULES with OT/maritime-specific attack patterns.
// Covers NMEA, AIS, Modbus, serial port manipulation, and vessel system attacks.
// @rule:KAV-020 Domain signatures are EE-only — not in OSS DEFAULT_RULES

import type { ShieldRules } from "./injection-detector";

// Maritime-specific path prefixes for serial/OT access
export const MARITIME_SENSITIVE_PATHS = [
  "/dev/ttyS",       // serial ports (NMEA, Modbus)
  "/dev/ttyUSB",     // USB-serial adapters
  "/dev/ttyACM",     // CDC ACM serial
  "/dev/ttyAMA",     // UART on embedded
  "/proc/net/arp",   // ARP table (vessel network mapping)
];

// Modbus/OT port patterns — if agent reads or writes to these ports it is suspect
export const MARITIME_EXFIL_COMMANDS = [
  "modpoll",         // Modbus poll CLI
  "mbpoll",          // another Modbus tool
  "nmap.*502",       // port 502 scan (Modbus TCP)
  "nc.*502",
  "socat.*ttyS",     // bridge serial to network
];

export const MARITIME_INJECTION_PATTERNS: ShieldRules["injection_patterns"] = [
  // NMEA sentence injection — malformed $GPGGA / $GPRMC used to spoof GPS
  {
    id: "MAR-001",
    pattern: "\\$GP(GGA|RMC|VTG|GLL|ZDA|GSA|GSV),[0-9,\\.]+\\*[0-9A-Fa-f]{2}",
    flags: "g",
    severity: "BLOCK",
    reason: "NMEA sentence injection — potential GPS/position spoofing via crafted sentence",
  },
  // AIS VDM/VDO payload — forged AIS broadcast in agent context
  {
    id: "MAR-002",
    pattern: "!AIVD[MO],[0-9],[0-9],[0-9]?,[AB],[A-z0-9<>=?@`]{1,56},[0-5]\\*[0-9A-Fa-f]{2}",
    flags: "g",
    severity: "BLOCK",
    reason: "AIS VDM/VDO payload — AIS message injection or spoofing attempt",
  },
  // Modbus function code 6/16 (write single/multiple registers) in hex payload
  {
    id: "MAR-003",
    pattern: "\\b(0x)?(06|10)\\s+(0x)?[0-9A-Fa-f]{4}\\s+(0x)?[0-9A-Fa-f]{4}",
    flags: "i",
    severity: "WARN",
    reason: "Modbus write register command pattern detected in agent input",
  },
  // Attempt to override autopilot / navigation heading
  {
    id: "MAR-004",
    pattern: "set\\s+(autopilot|heading|rudder|throttle|engine)\\s+(to|=)\\s*[\\-0-9]+",
    flags: "i",
    severity: "QUARANTINE",
    reason: "Navigation control injection — attempt to set autopilot/heading/throttle via agent",
  },
  // ECDIS/chart system command injection
  {
    id: "MAR-005",
    pattern: "ecdis|navionics|chart\\s+server|route\\s+plan.*overrid",
    flags: "i",
    severity: "BLOCK",
    reason: "ECDIS/chart system injection — attempt to manipulate navigation chart data",
  },
  // Alarm suppression / sensor defeat patterns (HC detector disable = runaway diesel attack)
  {
    id: "MAR-006",
    pattern: "(suppress|disable|silence|bypass|override)\\s+(alarm|alert|sensor|detector|shutdown|safety)",
    flags: "i",
    severity: "QUARANTINE",
    reason: "Safety system bypass — attempt to suppress alarms or safety shutdowns (diesel runaway vector)",
  },
  // Engine room OT — Modbus holding register address range for fuel/engine systems
  {
    id: "MAR-007",
    pattern: "(holding|input|coil)\\s+register\\s+(0x)?[4-9][0-9A-Fa-f]{3}",
    flags: "i",
    severity: "WARN",
    reason: "OT register range typical of engine/fuel Modbus map — verify intent",
  },
  // STCW duty manipulation — watch schedule injection
  {
    id: "MAR-008",
    pattern: "(watch\\s+schedule|duty\\s+roster|officer.*watch).*overrid",
    flags: "i",
    severity: "BLOCK",
    reason: "STCW watch schedule manipulation — attempt to override officer duty roster",
  },
];

// Merge maritime signatures into a ShieldRules-compatible override object
export function getMaritimeRuleOverride(): Partial<ShieldRules> {
  return {
    injection_patterns: MARITIME_INJECTION_PATTERNS,
    persistence_targets: MARITIME_SENSITIVE_PATHS,
    exfil_commands: MARITIME_EXFIL_COMMANDS,
  };
}
