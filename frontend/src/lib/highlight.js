// Tiny token-based syntax highlighter for Rego and JSON.
// Returns React-friendly { html: string }.

const REGO_KEYWORDS = new Set([
  "package", "import", "if", "else", "default", "not", "in", "contains",
  "every", "some", "as", "with", "true", "false", "null",
]);

const REGO_BUILTINS = new Set([
  "regex", "match", "startswith", "endswith", "lower", "upper",
  "count", "sum", "max", "min", "sprintf", "json",
]);

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function highlightRego(src) {
  if (!src) return "";
  // Tokenize line-by-line so comments/strings don't bleed.
  const lines = src.split("\n");
  const out = [];

  for (const line of lines) {
    let i = 0;
    let html = "";

    while (i < line.length) {
      const c = line[i];

      // Comment: # to end of line
      if (c === "#") {
        html += `<span class="tok-com">${escapeHtml(line.slice(i))}</span>`;
        break;
      }

      // String literal
      if (c === '"') {
        let j = i + 1;
        while (j < line.length && line[j] !== '"') {
          if (line[j] === "\\") j++; // skip escape
          j++;
        }
        const str = line.slice(i, Math.min(j + 1, line.length));
        html += `<span class="tok-str">${escapeHtml(str)}</span>`;
        i = j + 1;
        continue;
      }

      // Number
      if (/\d/.test(c) || (c === "-" && /\d/.test(line[i + 1] || ""))) {
        let j = i + 1;
        while (j < line.length && /[\d.]/.test(line[j])) j++;
        html += `<span class="tok-num">${escapeHtml(line.slice(i, j))}</span>`;
        i = j;
        continue;
      }

      // Identifier / keyword
      if (/[a-zA-Z_]/.test(c)) {
        let j = i + 1;
        while (j < line.length && /[a-zA-Z0-9_]/.test(line[j])) j++;
        const word = line.slice(i, j);
        if (REGO_KEYWORDS.has(word)) {
          if (word === "true" || word === "false" || word === "null") {
            html += `<span class="tok-bool">${word}</span>`;
          } else {
            html += `<span class="tok-kw">${word}</span>`;
          }
        } else if (REGO_BUILTINS.has(word)) {
          html += `<span class="tok-key">${word}</span>`;
        } else {
          html += `<span class="tok-ident">${word}</span>`;
        }
        i = j;
        continue;
      }

      // Operators
      if ("=!<>".includes(c)) {
        let op = c;
        if (line[i + 1] === "=") op += "=";
        html += `<span class="tok-op">${escapeHtml(op)}</span>`;
        i += op.length;
        continue;
      }

      // Punctuation
      if ("(){}[],;.:".includes(c)) {
        html += `<span class="tok-pun">${escapeHtml(c)}</span>`;
        i++;
        continue;
      }

      html += escapeHtml(c);
      i++;
    }

    out.push(html);
  }
  return out.join("\n");
}

export function highlightJson(src) {
  if (!src) return "";
  const out = [];
  const n = src.length;
  let i = 0;

  while (i < n) {
    const c = src[i];

    // String — distinguish key (followed by :) from value
    if (c === '"') {
      let j = i + 1;
      while (j < n && src[j] !== '"') {
        if (src[j] === "\\") j++;
        j++;
      }
      const str = src.slice(i, Math.min(j + 1, n));
      let k = j + 1;
      while (k < n && /\s/.test(src[k])) k++;
      const cls = src[k] === ":" ? "tok-key" : "tok-str";
      out.push(`<span class="${cls}">${escapeHtml(str)}</span>`);
      i = j + 1;
      continue;
    }

    // Number
    if (/[\d-]/.test(c)) {
      const rest = src.slice(i);
      const m = rest.match(/^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/);
      if (m && (c !== "-" || /\d/.test(src[i + 1] || ""))) {
        out.push(`<span class="tok-num">${m[0]}</span>`);
        i += m[0].length;
        continue;
      }
    }

    // Boolean / null
    if (c === "t" || c === "f" || c === "n") {
      const rest = src.slice(i);
      const m = rest.match(/^(true|false|null)\b/);
      if (m) {
        out.push(`<span class="tok-bool">${m[0]}</span>`);
        i += m[0].length;
        continue;
      }
    }

    // Punctuation
    if ("{}[],".includes(c)) {
      out.push(`<span class="tok-pun">${escapeHtml(c)}</span>`);
      i++;
      continue;
    }

    out.push(escapeHtml(c));
    i++;
  }

  return out.join("");
}
