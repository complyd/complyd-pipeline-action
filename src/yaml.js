'use strict';

/**
 * A strict reader for the YAML subset `.complyd/ai.yml` needs (the action
 * ships no dependencies): block mappings and sequences by indentation,
 * `[a, b]` and `{ k: v }` of scalars, quoted and plain scalars, comments.
 * Anything else (anchors, tags, block scalars `|` `>`, several documents) is
 * refused with the line to fix rather than read wrongly.
 */

class YamlError extends Error {}

const fail = (n, why) => {
  throw new YamlError(`line ${n}: ${why}`);
};

/** The line without its comment (`#` at the start or after a space, outside quotes). */
function stripComment(text) {
  let q = null;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (q) {
      if (c === '\\' && q === '"') i += 1;
      else if (c === q) q = null;
    } else if (c === '"' || c === "'") q = c;
    else if (c === '#' && (i === 0 || /\s/.test(text[i - 1]))) return text.slice(0, i);
  }
  return text;
}

/** One scalar: quoted, or plain (true/false/null/numbers typed). */
function scalar(raw, n) {
  const s = raw.trim();
  if (s.startsWith('"')) {
    if (!s.endsWith('"') || s.length < 2) fail(n, 'a "quoted" value is not closed');
    try {
      return JSON.parse(s);
    } catch {
      fail(n, 'a "quoted" value has a bad escape');
    }
  }
  if (s.startsWith("'")) {
    if (!s.endsWith("'") || s.length < 2) fail(n, "a 'quoted' value is not closed");
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (s === '' || s === '~' || s === 'null') return null;
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (/^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(s)) return Number(s);
  if (/^[&*!|>%@`]/.test(s)) fail(n, `"${s[0]}" (anchors, tags, block text) is not supported: quote the value`);
  if (/^[[{]/.test(s)) fail(n, 'nested [ ] or { } is not supported: use indented lines');
  return s;
}

/** Splits `a, "b, c", d` on top-level commas. */
function splitFlow(body, n) {
  const parts = [];
  let q = null;
  let cur = '';
  for (let i = 0; i < body.length; i += 1) {
    const c = body[i];
    if (q) {
      if (c === '\\' && q === '"') {
        cur += c + (body[i + 1] ?? '');
        i += 1;
        continue;
      }
      if (c === q) q = null;
    } else if (c === '"' || c === "'") q = c;
    else if (c === ',') {
      parts.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  if (q) fail(n, 'a quoted value is not closed');
  parts.push(cur);
  if (parts.length === 1 && parts[0].trim() === '') return [];
  return parts;
}

/** `key: rest` → [key, rest], or null when the text isn't a mapping entry. */
function entry(text, n) {
  let key;
  let rest;
  if (text[0] === '"' || text[0] === "'") {
    const end = text.indexOf(text[0], 1);
    if (end < 0) fail(n, 'a quoted key is not closed');
    key = scalar(text.slice(0, end + 1), n);
    rest = text.slice(end + 1);
    if (!/^:(\s|$)/.test(rest)) return null;
    rest = rest.slice(1);
  } else {
    const m = /^([^:]+?):(\s|$)(.*)$/.exec(text);
    if (!m) return null;
    key = m[1].trim();
    rest = m[3];
  }
  return [String(key), rest.trim()];
}

/** A value on the key's own line: a flow collection or a scalar. */
function inline(rest, n) {
  if (rest.startsWith('[')) {
    if (!rest.endsWith(']')) fail(n, 'a [ list ] must close on the same line');
    return splitFlow(rest.slice(1, -1), n).map((p) => scalar(p, n));
  }
  if (rest.startsWith('{')) {
    if (!rest.endsWith('}')) fail(n, 'a { map } must close on the same line');
    const out = {};
    for (const p of splitFlow(rest.slice(1, -1), n)) {
      const e = entry(p.trim(), n);
      if (!e) fail(n, 'each { map } entry must be key: value');
      if (e[0] === '__proto__') fail(n, '"__proto__" is not a valid key');
      if (Object.hasOwn(out, e[0])) fail(n, `"${e[0]}" is listed twice`);
      out[e[0]] = scalar(e[1], n);
    }
    return out;
  }
  if (rest === '|' || rest === '>' || /^[|>][-+0-9]/.test(rest)) fail(n, 'block text (| or >) is not supported: use a quoted value');
  return scalar(rest, n);
}

/** text → the parsed document (an object, array, scalar or null). Throws YamlError naming the line. */
function parseYaml(text) {
  const lines = [];
  String(text)
    .replace(/^﻿/, '')
    .split(/\r?\n/)
    .forEach((raw, i) => {
      const n = i + 1;
      const body = stripComment(raw).trimEnd();
      if (!body.trim()) return;
      if (/^(---|\.\.\.)(\s|$)/.test(body)) {
        if (lines.length) fail(n, 'only one document per file');
        return;
      }
      const indent = /^ */.exec(body)[0].length;
      if (body[indent] === '\t') fail(n, 'indent with spaces, not tabs');
      lines.push({ n, indent, text: body.slice(indent) });
    });
  let i = 0;

  function block(indent) {
    const seq = lines[i].text === '-' || lines[i].text.startsWith('- ');
    return seq ? sequence(indent) : mapping(indent);
  }

  /** The value after `key:` or `-` with nothing on the line. */
  function child(parentIndent, allowSameIndentSeq) {
    const next = lines[i];
    if (!next) return null;
    if (next.indent > parentIndent) return block(next.indent);
    const isSeq = next.text === '-' || next.text.startsWith('- ');
    if (allowSameIndentSeq && next.indent === parentIndent && isSeq) return sequence(parentIndent);
    return null;
  }

  function mapping(indent) {
    const out = {};
    while (i < lines.length && lines[i].indent === indent) {
      const { n, text } = lines[i];
      if (text === '-' || text.startsWith('- ')) fail(n, 'a list item where a key was expected');
      const e = entry(text, n);
      if (!e) fail(n, 'expected key: value');
      const [key, rest] = e;
      if (key === '__proto__') fail(n, '"__proto__" is not a valid key');
      if (Object.hasOwn(out, key)) fail(n, `"${key}" is listed twice`);
      i += 1;
      out[key] = rest === '' ? child(indent, true) : inline(rest, n);
    }
    if (i < lines.length && lines[i].indent > indent) fail(lines[i].n, 'unexpected indentation');
    return out;
  }

  function sequence(indent) {
    const out = [];
    while (i < lines.length && lines[i].indent === indent && (lines[i].text === '-' || lines[i].text.startsWith('- '))) {
      const { n, text } = lines[i];
      const rest = text.slice(1).trim();
      if (rest === '') {
        i += 1;
        out.push(child(indent, false));
      } else if (!/^["'[{]/.test(rest) && entry(rest, n)) {
        // `- key: value`: a mapping whose keys sit where `key` starts.
        const at = indent + text.length - text.slice(1).trimStart().length;
        lines[i] = { n, indent: at, text: rest };
        out.push(mapping(at));
      } else {
        i += 1;
        out.push(inline(rest, n));
      }
    }
    if (i < lines.length && lines[i].indent > indent) fail(lines[i].n, 'unexpected indentation');
    return out;
  }

  if (!lines.length) return null;
  const doc = block(lines[0].indent);
  if (i < lines.length) fail(lines[i].n, 'unexpected indentation');
  return doc;
}

module.exports = { parseYaml, YamlError };
