export default function EmptyState({ onNew, onShowTemplates }) {
  return (
    <div className="editor">
      <div className="editor-empty">
        <div className="editor-empty-content">
          <h2>
            Build, test, and deploy <em>OPA policies</em> — without writing a line of Rego.
          </h2>
          <p>
            Compose decision rules visually, watch them compile to idiomatic Rego in real time,
            and exercise them in a live sandbox backed by an actual OPA engine. Templates cover
            KYC/AML, transaction limits, sanctions, stablecoin operations, custody approvals,
            and DeFi access control.
          </p>
          <div className="editor-empty-actions">
            <button className="btn btn-primary" onClick={onShowTemplates}>
              Browse Templates
            </button>
            <button className="btn" onClick={onNew}>
              Start Blank
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
