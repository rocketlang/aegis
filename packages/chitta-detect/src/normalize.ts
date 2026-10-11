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
  // Added in 0.3.1. Written as escapes, because most of them cannot be told from the Latin
  // letter on a screen. Cyrillic: palochka (both cases), izhitsa, omega, komi sje.
  'ӏ': 'l', 'Ӏ': 'l', 'ѵ': 'v', 'ѡ': 'w', 'ԍ': 'g',
  // Greek: lunate sigma (both cases), yot.
  'ϲ': 'c', 'Ϲ': 'C', 'ϳ': 'j',
  // Latin letters that are not the ASCII ones: dotless i and j, script a and g.
  'ı': 'i', 'ȷ': 'j', 'ɑ': 'a', 'ɡ': 'g',
  // Armenian: oh, seh, ho.
  'օ': 'o', 'ս': 'u', 'հ': 'h',
};
const LOOKALIKE_RE = new RegExp('[' + Object.keys(LOOKALIKES).join('') + ']', 'g');
const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i' };
const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

// What a reader sees: compatibility forms folded, invisible characters gone, markup and
// emphasis marks gone. Whitespace is left as written; ws() collapses it last, so that a
// wider gap between two spelled-out words is still there when fold() joins the letters.
// A comment opener is first swapped for one character that cannot be in the text any more
// (the invisible characters were just removed), so that "anything up to the closer" can be
// written as a run of single characters with no opener in it. Many openers and no closer
// then cost one pass, not one long look-ahead each.
const COMMENT_OPEN = '⁣';
const COMMENT = /⁣[^⁣]{0,4000}?-->|⁣/g;

function rendered(s: string): string {
  return s
    .normalize('NFKC')
    .replace(INVISIBLE, '')
    // A comment renders as nothing at all; a tag, as a break between what stands on either side.
    // Through 0.3.0 a comment was left in place, and a tag was removed only when its attributes
    // were 60 characters or fewer: `<span class="…70 characters…">` kept a phrase from matching.
    .replace(/<!--/g, COMMENT_OPEN).replace(COMMENT, '')
    .replace(/<\/?[a-zA-Z][^<>]{0,4000}>/g, ' ')
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
  // Accents come off FIRST, and look-alike letters are mapped after. Through 0.3.0 it was the
  // other way round, so a look-alike that also carried an accent (Greek ό, Cyrillic ё) was
  // not in the table when it was looked up, lost its accent afterwards, and stayed foreign.
  return s
    .normalize('NFD')
    .replace(/\p{M}+/gu, '')
    .normalize('NFC')
    .replace(LOOKALIKE_RE, (c) => LOOKALIKES[c] ?? c)
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
function foldLeet(s: string, one: 'i' | 'l' | 'both' = 'i'): string {
  return s.replace(/[A-Za-z0-9@$!]+/g, (w) => {
    if (!(/[A-Za-z]/.test(w) && /[0-9@$!]/.test(w))) return w;
    // 'both': a doubled 1 is read as "ll" and a single one as "i" ("1gnore a11").
    const word = one === 'both' ? w.replace(/11/g, 'll') : w;
    return word.replace(/[013457@$!]/g, (c) => (c === '1' ? (one === 'l' ? 'l' : 'i') : LEET[c] ?? c));
  });
}

// Never matched by a pattern and never collapsed into a space: keeps two readings of the same
// text apart, so that no phrase is made from the end of one and the start of the other.
const APART = ' ¦ ';

// The digit 1 stands for "i" in one word and for "l" in the next ("1gnore", "a11"). Both
// readings are given, and a third in which a doubled 1 is "ll" and a single one "i", for a
// text that uses it both ways. Through 0.3.0 only "i" was tried, so "a11" for "all" was not
// seen. A text that mixes the two meanings in some other way is still not read.
function leetReadings(s: string): string {
  const asI = foldLeet(s, 'i');
  const asL = foldLeet(s, 'l');
  if (asL === asI) return asI;
  const both = foldLeet(s, 'both');
  return asI + APART + asL + (both === asI || both === asL ? '' : APART + both);
}

function readable(text: string): string | null {
  const printable = text.replace(/[^\x20-\x7e\n]/g, '');
  return text.length >= 8 && printable.length / text.length > 0.9 && /[A-Za-z]{3}/.test(printable) ? printable : null;
}

// Base64 (standard or URL-safe) and hex runs that decode to readable text. Capped in
// count and length, so a large blob cannot be used to slow a scan.
//
// Through 0.3.0 only the first 8 runs of a text were tried. Ordinary documents are full of
// long tokens (links, hashes, identifiers), so a payload lower down was never decoded. The
// limit is now on the work done, not on where in the text a run stands: up to MAX_RUNS runs
// and MAX_DECODED characters of them, each run cut at 4096.
const RUN = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
const MAX_RUNS = 256;
const MAX_DECODED = 256 * 1024;

function decodeOne(run: string): string | null {
  const cut = run.slice(0, 4096);
  if (/^[0-9a-fA-F]+$/.test(cut) && cut.length % 2 === 0) return readable(Buffer.from(cut, 'hex').toString('utf8'));
  try {
    return readable(Buffer.from(cut.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch {
    return null; // not base64 after all
  }
}

function decodeRuns(s: string): string {
  const out: string[] = [];
  const runs = (s.match(RUN) ?? []).slice(0, MAX_RUNS);
  let budget = MAX_DECODED;
  const take = (run: string): void => {
    if (budget <= 0) return;
    budget -= Math.min(run.length, 4096);
    const r = decodeOne(run);
    if (!r) return;
    out.push(r);
    // Encoded once more: what came out is itself one run and nothing else. One level only.
    const inner = r.trim();
    if (/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(inner)) {
      const r2 = decodeOne(inner);
      if (r2) out.push(r2);
    }
  };
  for (const run of runs) take(run);
  // Base64 wrapped at a column: lines of one length, the last one shorter or equal, with
  // only white space between them. Each line decodes on its own into a piece of the text,
  // with the phrase cut wherever the line ended, so the lines are also tried as one run.
  //
  // Found by walking the words once, not by a pattern over the whole text: a pattern with a
  // repeat inside a repeat took 39 seconds on one unbroken 270 KB run.
  const LINE = /^[A-Za-z0-9+/_-]{16,}$/;
  const LAST = /^[A-Za-z0-9+/_-]{2,}={0,2}$/;
  const words = s.split(/\s+/, 20000);
  let blocks = 0;
  for (let i = 0; i < words.length && blocks < 16; i++) {
    const width = words[i].length;
    if (width > 512 || !LINE.test(words[i])) continue;
    let j = i + 1;
    while (j < words.length && j - i < 64 && words[j].length === width && LINE.test(words[j])) j++;
    // the last line of a wrapped block is shorter, or the same length
    const hasTail = j < words.length && j - i < 64 && words[j].length < width && LAST.test(words[j]);
    const end = hasTail ? j + 1 : j;
    if (end - i >= 2) { take(words.slice(i, end).join('')); blocks++; i = end - 1; }
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
  const v4 = leetReadings(dec) + (runs ? APART + ws(fold(rendered(runs))) : '');
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
