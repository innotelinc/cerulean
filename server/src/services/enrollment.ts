import { randomUUID } from "node:crypto";
import { X509Certificate } from "node:crypto";
import { config } from "../config";
import { db } from "../db";
import { NAME_RE } from "./pki";

/**
 * Device enrollment artifacts: an Apple configuration profile (.mobileconfig)
 * that installs the Cerulean root CA as a trust anchor and asks the device to
 * obtain its TLS client certificate from the SCEP endpoint configured in
 * `PKI_SCEP_URL`. Push the profile through any MDM (fleet, MicroMDM, ...) or
 * install it directly on a managed Mac — the device then presents that
 * certificate to nginx proxy manager for automatic access.
 *
 * The profile is intentionally unsigned: MDM-delivered configuration profiles
 * do not require a signature. Manually installed ones show macOS's standard
 * "unsigned profile" warning.
 */

export class EnrollmentError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "EnrollmentError";
  }
}

/** XML-escape a value for embedding in a plist payload. */
function esc(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export interface EnrollmentProfile {
  filename: string;
  xml: string;
}

export function buildEnrollmentProfile(input: { name: string }): EnrollmentProfile {
  const name = input.name.trim();
  if (!NAME_RE.test(name)) {
    throw new EnrollmentError(
      400,
      `Invalid device name "${name}" — letters, digits, '.', '_' or '-', 1-64 chars`,
    );
  }
  const scepUrl = config.pki.scepUrl;
  if (!scepUrl) {
    throw new EnrollmentError(
      400,
      "PKI_SCEP_URL is not configured — set it in .env to the SCEP endpoint devices can reach",
    );
  }
  const ca = db.getCa();
  if (!ca) {
    throw new EnrollmentError(
      409,
      "Internal CA is not initialized yet — initialize it first (POST /api/pki/init)",
    );
  }

  const rootDerB64 = new X509Certificate(ca.certificate).raw.toString("base64");

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadDisplayName</key>
  <string>Cerulean device enrollment — ${esc(name)}</string>
  <key>PayloadIdentifier</key>
  <string>us.innotel.cerulean.pki.enroll.${esc(name)}</string>
  <key>PayloadOrganization</key>
  <string>Cerulean</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadScope</key>
  <string>System</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${randomUUID()}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>us.innotel.cerulean.pki.root</string>
      <key>PayloadUUID</key>
      <string>${randomUUID()}</string>
      <key>PayloadDisplayName</key>
      <string>Cerulean Root CA</string>
      <key>PayloadContent</key>
      <data>${rootDerB64}</data>
    </dict>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.scep</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>us.innotel.cerulean.pki.scep</string>
      <key>PayloadUUID</key>
      <string>${randomUUID()}</string>
      <key>PayloadDisplayName</key>
      <string>Cerulean SCEP enrollment</string>
      <key>URL</key>
      <string>${esc(scepUrl)}</string>
      <key>Name</key>
      <string>${esc(config.pki.scepCaName)}</string>
      <key>Subject</key>
      <array>
        <array>
          <array>
            <string>CN</string>
            <string>${esc(name)}</string>
          </array>
        </array>
      </array>
      <key>Keysize</key>
      <integer>2048</integer>${config.pki.scepChallenge ? `\n      <key>Challenge</key>\n      <string>${esc(config.pki.scepChallenge)}</string>` : ""}
    </dict>
  </array>
</dict>
</plist>
`;

  return { filename: `cerulean-${name}.mobileconfig`, xml };
}
