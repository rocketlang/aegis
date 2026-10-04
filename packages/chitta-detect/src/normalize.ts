// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// See LICENSE for details.

// @rule:CG-014 — a detector matches the text a reader would see, not the bytes an attacker chose
//
// Every detector in this package is a regular expression. Run on raw text, each one is
// defeated by the first disguise anyone would try: an invisible character inside a
// keyword, a Cyrillic letter that looks like a Latin one, a tag or a line break between
// two words, digits standing in for letters, or the instruction in base64.
//
// views() returns the forms of a text that the detectors run on. The original text is
// never changed; these strings exist only to be matched against.
//
// Not every view is equal evidence. Removing an invisible character or decoding base64
// undoes something nobody does by accident. Turning `ignore_previous` or `system-override`
// into two words undoes something every codebase and manual does on purpose. So a view
// carries a KIND, and the orchestrator treats a hit that exists only because separators
// were collapsed as ambiguous (see CG-015 in scan.ts).
//
// WHAT THIS DOES NOT COVER, on purpose and stated in the README: the same intent in other
// words, other languages, a keyword split by a space, and encodings other than base64,
// hex, HTML entities, URL-encoding and digit-for-letter. A pattern matcher cannot see
// those. Folding more would only make that less obvious.

export type ViewKind = 'literal' | 'folded' | 'collapsed' | 'decoded' | 'decoded-collapsed';
export interface View {
  kind: ViewKind;
  text: string;
  /** For a collapsed view: the index, in the same list, of the view it was collapsed from. */
  parent?: number;
}

// Zero-width and other format characters that render as nothing.
const INVISIBLE = /[­͏؜ᅟᅠ឴឵᠋-᠎​-‏‪-‮⁠-⁤⁦-⁯ㅤ︀-️﻿ﾠ]|\udb40[\udc00-\udc7f]/g;

// Cyrillic and Greek letters that are drawn like Latin ones.
const LOOKALIKES: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'У': 'Y', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S',
  'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
  'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
};
const LOOKALIKE_RE = new RegExp('[' + Object.keys(LOOKALIKES).join('') + ']', 'g');
const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i' };
const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

// What a reader sees: compatibility forms folded, invisible characters gone, markup and
// emphasis marks gone. Whitespace is left as written; ws() collapses it last, so that a
// wider gap between two spelled-out words is still there when fold() joins the letters.
function rendered(s: string): string {
  return s
    .normalize('NFKC')
    .replace(INVISIBLE, '')
    .replace(/<\/?[a-zA-Z][^<>]{0,60}>/g, ' ')
    .replace(/(?<![A-Za-z0-9])[*_`~]+|[*_`~]+(?![A-Za-z0-9])/g, '');
}

// All whitespace, line breaks included, as single spaces: a phrase broken across lines
// is the same phrase.
function ws(s: string): string {
  return s.replace(/\s+/g, ' ');
}

// Look-alike letters to Latin, accents and combining marks off, and letters spelled out
// with ONE repeated separator ("S.Y.S.T.E.M", "j|a|i|l", "S Y S T E M") joined. The
// separator must be the same throughout, so two spelled-out words stay two words. None
// of these happen by accident in a way that produces an English attack phrase.
function fold(s: string): string {
  return s
    .replace(LOOKALIKE_RE, (c) => LOOKALIKES[c] ?? c)
    .normalize('NFD')
    .replace(/\p{M}+/gu, '')
    .normalize('NFC')
    .replace(/\b[A-Za-z]([.\-_ |*/])[A-Za-z](?:\1[A-Za-z]){2,}\b/g, (m, sep: string) => m.split(sep).join(''));
}

// Separators between words become a space. This is what turns `ignore_previous` into a
// match, so hits that appear only here are treated as ambiguous by the orchestrator.
function collapse(s: string): string {
  return s.replace(/(?<=[A-Za-z0-9])[-_.|/\\~*]+(?=[A-Za-z0-9])/g, ' ').replace(/\s+/g, ' ');
}

function decodeEntitiesAndUrl(s: string): string {
  let out = s
    .replace(/&#x([0-9a-fA-F]{1,6});/g, (_, h) => String.fromCodePoint(Math.min(parseInt(h, 16), 0x10ffff)))
    .replace(/&#([0-9]{1,7});/g, (_, d) => String.fromCodePoint(Math.min(parseInt(d, 10), 0x10ffff)))
    .replace(/&([a-z]{2,5});/g, (m, n) => ENTITIES[n] ?? m);
  out = out.replace(/(?:%[0-9a-fA-F]{2})+/g, (m) => {
    try {
      return decodeURIComponent(m);
    } catch {
      return m;
    }
  });
  return out;
}

// Digits and symbols standing in for letters, only inside words that also hold letters,
// so an ordinary number ("2026", "09:00") is left alone.
function foldLeet(s: string): string {
  return s.replace(/[A-Za-z0-9@$!]+/g, (w) => (/[A-Za-z]/.test(w) && /[0-9@$!]/.test(w) ? w.replace(/[013457@$!]/g, (c) => LEET[c] ?? c) : w));
}

function readable(text: string): string | null {
  const printable = text.replace(/[^\x20-\x7e\n]/g, '');
  return text.length >= 8 && printable.length / text.length > 0.9 && /[A-Za-z]{3}/.test(printable) ? printable : null;
}

// Base64 (standard or URL-safe) and hex runs that decode to readable text. Capped in
// count and length, so a large blob cannot be used to slow a scan.
function decodeRuns(s: string): string {
  const out: string[] = [];
  for (const run of (s.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) ?? []).slice(0, 8)) {
    if (/^[0-9a-fA-F]+$/.test(run) && run.length % 2 === 0) {
      const r = readable(Buffer.from(run.slice(0, 4096), 'hex').toString('utf8'));
      if (r) out.push(r);
      continue;
    }
    try {
      const r = readable(Buffer.from(run.slice(0, 4096).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
      if (r) out.push(r);
    } catch {
      // not base64 after all
    }
  }
  return out.join(' ');
}

/**
 * The views of `content` that detectors match against:
 *   literal            what a reader sees
 *   folded             + look-alike letters, accents and spelled-out letters undone
 *   collapsed          + separators between words turned into spaces (ambiguous on its own)
 *   decoded            entities, URL-encoding, digit-for-letter, base64 and hex undone
 *   decoded-collapsed  the decoded view with separators collapsed (ambiguous on its own)
 * Views identical to an earlier one are dropped, so plain prose costs one or two passes.
 */
export function views(content: string): View[] {
  const base = rendered(String(content ?? ''));
  const v1 = ws(base);
  const v2 = ws(fold(base));
  const dec = ws(fold(rendered(decodeEntitiesAndUrl(base))));
  const runs = decodeRuns(v1);
  const v4 = foldLeet(dec) + (runs ? ' ' + ws(fold(rendered(runs))) : '');
  const list: View[] = [];
  const seen = new Map<string, number>();
  const add = (kind: ViewKind, text: string, parentText?: string): void => {
    if (seen.has(text)) return;
    const parent = parentText === undefined ? undefined : seen.get(parentText);
    seen.set(text, list.length);
    list.push(parent === undefined ? { kind, text } : { kind, text, parent });
  };
  add('literal', v1);
  add('folded', v2);
  add('collapsed', collapse(v2), v2);
  add('decoded', v4);
  add('decoded-collapsed', collapse(v4), v4);
  return list;
}

/** The view texts only, for a detector that just needs to know whether anything matches. */
export function variants(content: string): string[] {
  return views(content).map((v) => v.text);
}
