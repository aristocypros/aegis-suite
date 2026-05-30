import { useEffect, useState, useRef } from "react";
import { api } from "../lib/api.js";
import { highlightRego } from "../lib/highlight.js";

// Read-only viewer for the compiled Rego source. The visual spec is the
// source of truth; this pane is recomputed by the backend compiler whenever
// the policy spec changes (debounced).
export default function RegoViewer({ policy }) {
  const [rego, setRego] = useState("");
  const [error, setError] = useState(null);
  const [compiling, setCompiling] = useState(false);
  const [copied, setCopied] = useState(false);
  const debounceRef = useRef(null);

  // Debounced compile on policy changes.
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    setCompiling(true);
    debounceRef.current = setTimeout(async () => {
      try {
        const res = await api.compile(policy);
        setRego(res.rego || "");
        setError(null);
      } catch (e) {
        setRego("");
        const msg = e.body?.details
          ? `${e.message}\n\n${typeof e.body.details === "string" ? e.body.details : JSON.stringify(e.body.details, null, 2)}`
          : e.message;
        setError(msg);
      } finally {
        setCompiling(false);
      }
    }, 250);
    return () => clearTimeout(debounceRef.current);
  }, [policy]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(rego);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };

  const lineCount = rego ? rego.split("\n").length : 0;

  return (
    <div className="code-pane">
      <div className="code-head">
        <div className="code-label">
          <strong>rego</strong> &nbsp;·&nbsp; compiled output
          {compiling && <span style={{ marginLeft: 10, color: "var(--text-dim)" }}>compiling…</span>}
          {!compiling && rego && (
            <span style={{ marginLeft: 10, color: "var(--text-dim)" }}>
              {lineCount} lines
            </span>
          )}
        </div>
        <div className="code-tools">
          <button
            className="btn btn-ghost btn-sm"
            onClick={handleCopy}
            disabled={!rego}
          >
            {copied ? "Copied ✓" : "Copy"}
          </button>
        </div>
      </div>

      <div className="code-body">
        {rego ? (
          <pre dangerouslySetInnerHTML={{ __html: highlightRego(rego) }} />
        ) : !error ? (
          <pre style={{ color: "var(--text-dim)" }}>
            {compiling ? "// compiling…" : "// no output yet"}
          </pre>
        ) : null}
      </div>

      {error && (
        <div className="code-error">
          <strong>Compile error</strong>
          <pre style={{ margin: "6px 0 0", whiteSpace: "pre-wrap", fontSize: 11.5 }}>
            {error}
          </pre>
        </div>
      )}
    </div>
  );
}
