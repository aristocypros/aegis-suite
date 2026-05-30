import { useState } from "react";
import { api } from "../lib/api.js";
import { setToken } from "../lib/auth.js";

export default function LoginPage({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (busy) return;
    setError(null);
    setBusy(true);
    try {
      const { token, user } = await api.login(username.trim(), password);
      setToken(token);
      onLogin(user);
    } catch (err) {
      setError(err?.body?.error || err.message || "Login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-shell">
      <form className="login-card" onSubmit={handleSubmit} autoComplete="on">
        <div className="login-brand">
          <div className="login-brand-mark">/0</div>
          <div>
            <div className="login-brand-title">
              Aegis Policy <em>Fabric</em>
            </div>
            <span className="login-brand-subtitle">OPA · ADMIN CONSOLE</span>
          </div>
        </div>

        <h1 className="login-heading">Sign in</h1>
        <p className="login-sub">Enter your administrator credentials to continue.</p>

        {error && <div className="auth-error">{error}</div>}

        <div className="field">
          <label className="field-label" htmlFor="login-user">Username</label>
          <input
            id="login-user"
            className="field-input"
            type="text"
            autoComplete="username"
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={busy}
          />
        </div>

        <div className="field">
          <label className="field-label" htmlFor="login-pw">Password</label>
          <input
            id="login-pw"
            className="field-input"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
          />
        </div>

        <div className="login-actions">
          <button
            type="submit"
            className="btn btn-primary"
            disabled={busy || !username || !password}
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </div>

        <div className="login-footer">On-prem deployment · v1</div>
      </form>
    </div>
  );
}
