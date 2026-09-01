import { useEffect, useState } from "react";
import { api, setToken } from "../api";
import type { AuthConfig } from "../types";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [authConfig, setAuthConfig] = useState<AuthConfig | null>(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.authConfig().then(setAuthConfig).catch(() => setAuthConfig(null));
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const { token } = await api.login(password);
      setToken(token);
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  };

  const signInWithAuthentik = () => {
    window.location.href = "/api/auth/oidc/authorize";
  };

  const oidcEnabled = Boolean(authConfig?.oidc.enabled);
  const localEnabled = authConfig ? authConfig.localEnabled : true;

  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={submit}>
        <div className="brand">
          <span className="brand-mark">◆</span>
          <span>Cerulean</span>
        </div>
        <p className="subtitle">Certificate &amp; DNS Management</p>

        {oidcEnabled && (
          <>
            <button
              type="button"
              onClick={signInWithAuthentik}
              style={{ width: "100%" }}
            >
              Sign in with Authentik
            </button>
            {localEnabled && <p className="muted divider">or with the admin password</p>}
          </>
        )}

        {localEnabled ? (
          <>
            <div className="form-row">
              <label htmlFor="pw">Admin password</label>
              <input
                id="pw"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoFocus={!oidcEnabled}
                style={{ flex: 1 }}
              />
            </div>
            {error && <p className="error">{error}</p>}
            <button type="submit" disabled={busy} style={{ width: "100%" }}>
              {busy ? "Signing in…" : "Sign in"}
            </button>
          </>
        ) : (
          !oidcEnabled && (
            <p className="error">No authentication method is configured.</p>
          )
        )}
      </form>
    </div>
  );
}
