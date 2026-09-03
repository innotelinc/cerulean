import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { ClientCertificate, PkiStatus } from "../types";

function downloadFile(
  filename: string,
  content: string,
  type = "application/x-pem-file",
) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function shortFingerprint(fp: string | null): string {
  if (!fp) return "—";
  return fp.replace(/:/g, "").slice(0, 16).toUpperCase();
}

export default function Pki() {
  const [status, setStatus] = useState<PkiStatus | null>(null);
  const [certs, setCerts] = useState<ClientCertificate[]>([]);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [busy, setBusy] = useState(false);

  // CA panels
  const [commonName, setCommonName] = useState("");
  const [caRevealed, setCaRevealed] = useState(false);
  const [caPem, setCaPem] = useState("");

  // issue form
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");

  // enrollment
  const [enrollName, setEnrollName] = useState("");

  // detail modal
  const [detail, setDetail] = useState<ClientCertificate | null>(null);
  const [material, setMaterial] = useState<{
    certificate: string;
    key: string | null;
    ca: string;
  } | null>(null);

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(""), 4000);
  };

  const load = useCallback(async () => {
    try {
      const [s, c] = await Promise.all([
        api.pkiStatus(),
        api.pkiCertificates(),
      ]);
      setStatus(s);
      setCerts(c);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load PKI status");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const initCa = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const s = await api.pkiInit(commonName.trim() || undefined);
      setStatus(s);
      flash(s.initialized ? "Root CA generated" : "Root CA is ready");
      setCommonName("");
      setCaRevealed(false);
      setCaPem("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to initialize the CA");
    } finally {
      setBusy(false);
    }
  };

  const toggleCa = async () => {
    if (caRevealed) {
      setCaRevealed(false);
      return;
    }
    try {
      const ca = await api.pkiCa();
      setCaPem(ca.certificate);
      setCaRevealed(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load the CA certificate");
    }
  };

  const downloadCa = async () => {
    try {
      const ca = await api.pkiCa();
      downloadFile("cerulean-ca.pem", ca.certificate);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to download the CA certificate");
    }
  };

  const issue = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError("");
    try {
      const cert = await api.issuePkiCertificate({
        name: name.trim(),
        email: email.trim() || undefined,
      });
      flash(`Client certificate issued for ${cert.name} (serial ${cert.serial})`);
      setName("");
      setEmail("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to issue certificate");
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (c: ClientCertificate) => {
    if (!window.confirm(`Revoke the client certificate for ${c.name}?`)) return;
    try {
      await api.revokePkiCertificate(c.id);
      flash(`Certificate for ${c.name} revoked`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Revocation failed");
    }
  };

  const showDetail = async (c: ClientCertificate) => {
    setDetail(c);
    setMaterial(null);
    if (c.status !== "issued") return;
    try {
      setMaterial(await api.pkiCertificateMaterial(c.id));
    } catch {
      setMaterial(null);
    }
  };

  const downloadMaterial = (c: ClientCertificate) => {
    if (!material) return;
    const bundle = [
      "# Cerulean device certificate — " + c.name,
      "# Serial: " + c.serial,
      "# Installed by the enrolling device; the private key never leaves it.",
      "",
      material.certificate,
      ...(material.key
        ? [material.key]
        : ["# (no key here — this certificate was CSR-enrolled; the key is on the device)"]),
      material.ca,
    ].join("\n");
    downloadFile(`${c.name}.pem`, bundle);
    flash(
      material.key
        ? "Downloaded device bundle (leaf + key + root CA)"
        : "Downloaded device bundle (leaf + root CA — key is on the device)",
    );
  };

  const downloadProfile = async () => {
    if (!enrollName.trim()) return;
    setError("");
    try {
      const xml = await api.pkiEnrollmentProfile(enrollName.trim());
      downloadFile(
        `cerulean-${enrollName.trim()}.mobileconfig`,
        xml,
        "application/x-apple-aspen-config",
      );
      flash("Enrollment profile downloaded — push it through your MDM");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to build the enrollment profile");
    }
  };

  const statusBadge = (c: ClientCertificate) =>
    c.status === "revoked" ? (
      <span className="badge red">revoked</span>
    ) : (
      <span className="badge green">issued</span>
    );

  const daysLeft = (iso: string | null) => {
    if (!iso) return null;
    return Math.round((new Date(iso).getTime() - Date.now()) / 86400000);
  };

  return (
    <div>
      <h1>PKI &amp; Devices</h1>
      <p className="subtitle">
        Cerulean's internal root CA and TLS client certificates for device /
        identity mTLS — reverse proxies, MDM enrollment, and service auth.
      </p>

      {error && <p className="error">{error}</p>}

      <div className="cards">
        <div className="card">
          <div className="num" style={{ color: status?.initialized ? undefined : "var(--amber)", fontSize: 20 }}>
            {status?.initialized ? "Ready" : "Not initialized"}
          </div>
          <div className="label">Internal root CA</div>
        </div>
        <div className="card">
          <div className="num">{status?.initialized ? `${daysLeft(status?.caExpiresAt ?? null)} days` : "—"}</div>
          <div className="label">CA expires in</div>
        </div>
        <div className="card">
          <div className="num">{status?.issued ?? 0}</div>
          <div className="label">Device certificates issued</div>
        </div>
        <div className="card">
          <div className="num">{status?.revoked ?? 0}</div>
          <div className="label">Revoked</div>
        </div>
      </div>

      {!status?.initialized ? (
        <div className="panel">
          <div className="panel-title">Initialize the internal CA</div>
          <p className="muted" style={{ marginTop: 0 }}>
            Cerulean will generate a self-signed ECDSA P-256 root CA. Install
            the CA certificate as a trust anchor on your nginx proxy manager,
            browsers, and MDM so devices presenting a certificate it signs are
            accepted.
          </p>
          <form className="form-row" onSubmit={initCa}>
            <input
              placeholder="CA common name (default: Cerulean Root CA)"
              value={commonName}
              onChange={(e) => setCommonName(e.target.value)}
              style={{ minWidth: 320 }}
            />
            <button type="submit" disabled={busy}>
              {busy ? "Generating…" : "Generate root CA"}
            </button>
          </form>
        </div>
      ) : (
        <>
          <div className="panel">
            <div className="panel-title">Root CA — {status?.commonName}</div>
            <p className="muted" style={{ marginTop: 0 }}>
              Fingerprint{" "}
              <span className="mono">
                {status?.caFingerprint?.slice(0, 47) || "—"}…
              </span>
              · Created {status?.createdAt ? new Date(status.createdAt).toLocaleDateString() : "—"} ·
              Expires {status?.caExpiresAt ? new Date(status.caExpiresAt).toLocaleDateString() : "—"}
            </p>
            <div className="actions">
              <button className="secondary small" onClick={toggleCa}>
                {caRevealed ? "Hide" : "View"} CA certificate
              </button>
              <button className="secondary small" onClick={downloadCa}>
                Download ca.pem
              </button>
            </div>
            {caRevealed && <textarea readOnly value={caPem} />}
          </div>

          <div className="panel">
            <div className="panel-title">Issue a device certificate</div>
            <form className="form-row" onSubmit={issue}>
              <input
                placeholder="device / identity name (e.g. laptop-1)"
                value={name}
                onChange={(e) => setName(e.target.value)}
                style={{ minWidth: 260 }}
              />
              <input
                placeholder="email (optional)"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={{ minWidth: 220 }}
              />
              <button type="submit" disabled={busy || !name.trim()}>
                {busy ? "Issuing…" : "Issue"}
              </button>
            </form>
            <p className="muted" style={{ margin: "4px 0 0" }}>
              Issued here, Cerulean generates and holds the private key. For
              enrollment where the key never leaves the device, use the MDM
              path below.
            </p>
          </div>

          <div className="panel">
            <div className="panel-title">Enroll devices through MDM (SCEP)</div>
            <p className="muted" style={{ marginTop: 0 }}>
              Download an Apple configuration profile for a device: it installs
              the root CA above as a trust anchor and asks the device to fetch
              its TLS client certificate from the SCEP endpoint set in{" "}
              <span className="mono">PKI_SCEP_URL</span> (point it at your SCEP
              server — see <span className="mono">docs/device-enrollment.md</span>).
              Push the profile through fleet / MicroMDM or install it on the
              Mac; the device then authenticates to nginx proxy manager with the
              certificate and is auto-allowed.
            </p>
            <form
              className="form-row"
              onSubmit={(e) => {
                e.preventDefault();
                downloadProfile();
              }}
            >
              <input
                placeholder="device CN (e.g. mbp-admin)"
                value={enrollName}
                onChange={(e) => setEnrollName(e.target.value)}
                style={{ minWidth: 260 }}
              />
              <button type="submit" disabled={!enrollName.trim()}>
                Download .mobileconfig
              </button>
            </form>
            <p className="muted" style={{ marginBottom: 6 }}>
              Enrolling programmatically (key stays on the machine):
            </p>
            <pre
              className="mono"
              style={{
                background: "var(--panel-2)",
                border: "1px solid var(--border)",
                borderRadius: 8,
                padding: 12,
                overflow: "auto",
                margin: 0,
              }}
            >
              {`openssl ecparam -name prime256v1 -genkey -noout -out device.key
openssl req -new -key device.key -subj "/CN=laptop-1" -out device.csr
CSR=$(sed ':a;N;$!ba;s/\n/\\n/g' device.csr)
curl -s -X POST https://cerulean.innotel.us/api/pki/enroll/csr \\
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d "{\"csr\": \"$CSR\"}"`}
            </pre>
          </div>
        </>
      )}

      <div className="panel">
        <div className="panel-title">Device certificates</div>
        {certs.length === 0 ? (
          <div className="empty">
            {status?.initialized
              ? "No client certificates issued yet"
              : "Initialize the CA to issue device certificates"}
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Serial</th>
                <th>Status</th>
                <th>Fingerprint</th>
                <th>Expires</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {certs.map((c) => {
                const days = daysLeft(c.expiresAt);
                return (
                  <tr key={c.id}>
                    <td>
                      <strong>{c.name}</strong>
                    </td>
                    <td className="muted">{c.email || "—"}</td>
                    <td className="mono">{c.serial}</td>
                    <td>{statusBadge(c)}</td>
                    <td className="mono">{shortFingerprint(c.fingerprint)}</td>
                    <td className={days !== null && days < 30 && c.status === "issued" ? "error" : "muted"}>
                      {c.expiresAt ? new Date(c.expiresAt).toLocaleDateString() : "—"}
                      {days !== null && c.status === "issued" && (
                        <span> ({days} days)</span>
                      )}
                    </td>
                    <td>
                      <div className="actions">
                        <button className="secondary small" onClick={() => showDetail(c)}>
                          View
                        </button>
                        {c.status === "issued" && (
                          <button className="danger small" onClick={() => revoke(c)}>
                            Revoke
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {detail && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 50,
          }}
          onClick={() => setDetail(null)}
        >
          <div
            className="panel"
            style={{ width: 760, maxHeight: "80vh", overflow: "auto", margin: 0 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="panel-title">
              {detail.name}
              {detail.status === "revoked" && (
                <span className="badge red" style={{ marginLeft: 10 }}>
                  revoked
                </span>
              )}
            </div>
            <p className="muted">
              Serial <span className="mono">{detail.serial}</span> · Issued:{" "}
              {detail.issuedAt ? new Date(detail.issuedAt).toLocaleString() : "—"} · Expires:{" "}
              {detail.expiresAt ? new Date(detail.expiresAt).toLocaleString() : "—"}
              {detail.revokedAt && (
                <>
                  {" "}
                  · Revoked: {new Date(detail.revokedAt).toLocaleString()}
                </>
              )}
              {detail.email && <> · {detail.email}</>}
            </p>
            {material ? (
              <>
                <div className="actions" style={{ marginBottom: 10 }}>
                  <button className="secondary small" onClick={() => downloadMaterial(detail)}>
                    Download bundle (.pem)
                  </button>
                </div>
                <p className="panel-title" style={{ marginBottom: 6 }}>
                  Device certificate (PEM)
                </p>
                <textarea readOnly value={material.certificate} />
                <p className="panel-title" style={{ marginBottom: 6 }}>
                  Private key (PEM)
                </p>
                {material.key ? (
                  <textarea readOnly value={material.key} />
                ) : (
                  <p className="muted">
                    No key stored — this certificate was CSR-enrolled and the
                    private key remains on the enrolling device.
                  </p>
                )}
                <p className="panel-title" style={{ marginBottom: 6 }}>
                  Root CA (PEM)
                </p>
                <textarea readOnly value={material.ca} />
              </>
            ) : (
              <p className="muted">
                {detail.status === "revoked"
                  ? "Revoked — material is no longer available."
                  : "Certificate material not available."}
              </p>
            )}
          </div>
        </div>
      )}

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
