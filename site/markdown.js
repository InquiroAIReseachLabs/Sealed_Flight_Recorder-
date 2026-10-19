// Shows a Sealed Flight Record report (SPEC B1.8) as a page. The report uses a small part of
// Markdown: headings, paragraphs, bullet lists, tables, fenced code, code spans, bold, and a
// backslash before ASCII punctuation in every value from the record. This renderer builds DOM
// nodes and sets only their text, never HTML, so nothing in a record (a log message, a file
// name) can become markup, a link, or a script.

const PUNCT = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';

function el(tag, parent) {
  const e = document.createElement(tag);
  if (parent) parent.appendChild(e);
  return e;
}

// Appends the inline content of `text` to `parent`: escapes, code spans, bold.
function inline(text, parent) {
  let node = parent;
  let buf = '';
  const flush = () => {
    if (buf) node.appendChild(document.createTextNode(buf));
    buf = '';
  };
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (c === '\\' && i + 1 < text.length && PUNCT.includes(text[i + 1])) {
      buf += text[i + 1];
      i += 1;
    } else if (c === '`') {
      const end = text.indexOf('`', i + 1);
      if (end < 0) {
        buf += c;
      } else {
        flush();
        el('code', node).textContent = text.slice(i + 1, end);
        i = end;
      }
    } else if (c === '*' && text[i + 1] === '*') {
      flush();
      if (node === parent) {
        node = el('strong', parent);
      } else {
        node = parent;
      }
      i += 1;
    } else {
      buf += c;
    }
  }
  flush();
}

// The cells of a table row: split at each `|` that is not escaped and not in a code span.
function cells(line) {
  let s = line.trim();
  if (s.startsWith('|')) s = s.slice(1);
  if (s.endsWith('|') && !s.endsWith('\\|')) s = s.slice(0, -1);
  const out = [];
  let cur = '';
  let code = false;
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (c === '\\' && !code && i + 1 < s.length) {
      cur += c + s[i + 1];
      i += 1;
    } else if (c === '`') {
      code = !code;
      cur += c;
    } else if (c === '|' && !code) {
      out.push(cur.trim());
      cur = '';
    } else {
      cur += c;
    }
  }
  out.push(cur.trim());
  return out;
}

const SEPARATOR = /^\|?(\s*:?-+:?\s*\|)+\s*:?-*:?\s*$/;

// Replaces the content of `container` with the rendered report. A heading of level n becomes an
// h(n + 2), under the page's own headings.
export function renderMarkdown(md, container) {
  container.replaceChildren();
  const lines = md.split('\n');
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.trim() === '') {
      i += 1;
    } else if (line.startsWith('```')) {
      const pre = el('pre', container);
      const code = el('code', pre);
      const body = [];
      i += 1;
      while (i < lines.length && !lines[i].startsWith('```')) {
        body.push(lines[i]);
        i += 1;
      }
      code.textContent = body.join('\n');
      i += 1;
    } else if (/^#{1,6} /.test(line)) {
      const level = line.indexOf(' ');
      inline(line.slice(level + 1), el(`h${Math.min(level + 2, 6)}`, container));
      i += 1;
    } else if (line.startsWith('|') && i + 1 < lines.length && SEPARATOR.test(lines[i + 1])) {
      const table = el('table', container);
      const head = el('tr', el('thead', table));
      for (const c of cells(line)) inline(c, el('th', head));
      const body = el('tbody', table);
      i += 2;
      while (i < lines.length && lines[i].startsWith('|')) {
        const tr = el('tr', body);
        for (const c of cells(lines[i])) inline(c, el('td', tr));
        i += 1;
      }
    } else if (line.startsWith('- ')) {
      const ul = el('ul', container);
      while (i < lines.length && lines[i].startsWith('- ')) {
        inline(lines[i].slice(2), el('li', ul));
        i += 1;
      }
    } else {
      const para = [];
      while (
        i < lines.length && lines[i].trim() !== '' && !lines[i].startsWith('```')
        && !/^#{1,6} /.test(lines[i]) && !lines[i].startsWith('- ')
        && !(lines[i].startsWith('|') && i + 1 < lines.length && SEPARATOR.test(lines[i + 1]))
      ) {
        para.push(lines[i]);
        i += 1;
      }
      inline(para.join(' '), el('p', container));
    }
  }
}
