import { useEffect, useState, useMemo } from "react";
import { api } from "../lib/api.js";

export default function TemplatesModal({ onSelect, onClose }) {
  const [templates, setTemplates] = useState([]);
  const [activeCat, setActiveCat] = useState("All");

  useEffect(() => {
    api.listTemplates().then(setTemplates).catch(() => setTemplates([]));
  }, []);

  const categories = useMemo(() => {
    const set = new Set(templates.map((t) => t.category));
    return ["All", ...[...set].sort()];
  }, [templates]);

  const filtered = activeCat === "All"
    ? templates
    : templates.filter((t) => t.category === activeCat);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2 className="modal-title">
            Template <em>Gallery</em>
          </h2>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        <div className="modal-body">
          <p style={{ color: "var(--text-muted)", fontSize: 13, marginTop: 0 }}>
            Pre-built starting points. Each template clones into a new policy you can customize, save, and deploy to OPA.
          </p>

          <div className="tpl-categories">
            {categories.map((c) => (
              <button
                key={c}
                className={`tpl-cat-btn ${c === activeCat ? "active" : ""}`}
                onClick={() => setActiveCat(c)}
              >
                {c}
              </button>
            ))}
          </div>

          <div className="tpl-grid">
            {filtered.map((t) => (
              <div key={t.id} className="tpl-card" onClick={() => onSelect(t.id)}>
                <div className="tpl-cat">{t.category}</div>
                <h3 className="tpl-name">{t.name}</h3>
                <p className="tpl-desc">{t.description}</p>
                <div className="tpl-pkg">{t.package}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
