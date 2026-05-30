import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api.js";

// Chip-input for free-form tags. Used by the policy-header tag editor and
// the caller scope-tags editor. Local state only — the parent decides when
// to persist (typically on blur via an onCommit callback).
//
// Props:
//   value:     string[]  current tags (normalised lowercase)
//   onCommit:  (next: string[]) => Promise<void>  called when the user adds
//              or removes a tag. Receives the new full array; caller is
//              responsible for the PATCH and any error display.
//   disabled:  boolean   read-only mode
//   placeholder: string  placeholder for the input
//   suggestions: string[] optional preloaded list; if omitted, lazy-fetches
//              from /api/tags on first focus.
const TAG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

export default function TagChipInput({
  value = [],
  onCommit,
  disabled = false,
  placeholder = "add tag…",
  suggestions: providedSuggestions = null,
}) {
  const [draft, setDraft] = useState("");
  const [error, setError] = useState(null);
  const [pending, setPending] = useState(false);
  const [suggestions, setSuggestions] = useState(providedSuggestions ?? []);
  const [showHints, setShowHints] = useState(false);
  const inputRef = useRef(null);
  const tags = Array.isArray(value) ? value : [];

  useEffect(() => {
    if (providedSuggestions !== null) {
      setSuggestions(providedSuggestions);
    }
  }, [providedSuggestions]);

  async function loadSuggestions() {
    if (providedSuggestions !== null) return;
    try {
      const { tags: all } = await api.listTags();
      setSuggestions(Array.isArray(all) ? all : []);
    } catch (_e) {
      // Best-effort; chip input still works without suggestions.
    }
  }

  async function commitNext(next) {
    setPending(true);
    setError(null);
    try {
      await onCommit(next);
    } catch (e) {
      setError(e?.body?.error || e.message || "Save failed");
    } finally {
      setPending(false);
    }
  }

  function tryAdd(rawValue) {
    const v = rawValue.trim().toLowerCase();
    if (!v) return;
    if (!TAG_RE.test(v)) {
      setError(`invalid tag '${rawValue}' — use a-z, 0-9, _, -`);
      return;
    }
    if (tags.includes(v)) {
      setDraft("");
      return;
    }
    const next = [...tags, v].sort();
    setDraft("");
    commitNext(next);
  }

  function tryRemove(t) {
    if (disabled || pending) return;
    const next = tags.filter((x) => x !== t);
    commitNext(next);
  }

  function handleKeyDown(e) {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      tryAdd(draft);
    } else if (e.key === "Backspace" && draft === "" && tags.length > 0) {
      tryRemove(tags[tags.length - 1]);
    }
  }

  // Filter suggestions to those not already selected + matching the draft.
  const filteredHints = suggestions
    .filter((s) => !tags.includes(s))
    .filter((s) => draft === "" || s.includes(draft.toLowerCase()))
    .slice(0, 8);

  return (
    <div className="tag-chip-input">
      <div className={`tag-chip-input-box ${disabled ? "disabled" : ""}`}>
        {tags.map((t) => (
          <span key={t} className="tag-chip-input-chip">
            {t}
            {!disabled && (
              <button
                type="button"
                className="tag-chip-input-remove"
                onClick={() => tryRemove(t)}
                disabled={pending}
                aria-label={`Remove tag ${t}`}
              >×</button>
            )}
          </span>
        ))}
        <input
          ref={inputRef}
          type="text"
          className="tag-chip-input-input"
          value={draft}
          onChange={(e) => { setDraft(e.target.value); setError(null); }}
          onKeyDown={handleKeyDown}
          onFocus={() => { setShowHints(true); loadSuggestions(); }}
          onBlur={() => setTimeout(() => setShowHints(false), 150)}
          disabled={disabled || pending}
          placeholder={tags.length === 0 ? placeholder : ""}
        />
      </div>
      {error && (
        <div className="tag-chip-input-error">{error}</div>
      )}
      {showHints && filteredHints.length > 0 && !disabled && (
        <div className="tag-chip-input-hints" role="listbox">
          {filteredHints.map((s) => (
            <div
              key={s}
              role="option"
              className="tag-chip-input-hint"
              onMouseDown={(e) => { e.preventDefault(); tryAdd(s); }}
            >
              {s}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
