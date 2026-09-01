import { describe, expect, it } from "vitest";
import { fqdn, parseZoneTransfer, quoteTxt } from "../src/services/bind";

describe("quoteTxt", () => {
  it("wraps values in quotes", () => {
    expect(quoteTxt("abc")).toBe('"abc"');
  });

  it("escapes quotes and backslashes", () => {
    expect(quoteTxt('a"b\\c')).toBe('"a\\"b\\\\c"');
  });
});

describe("fqdn", () => {
  it("qualifies relative names against the zone", () => {
    expect(fqdn("www", "innotel.us")).toBe("www.innotel.us.");
    expect(fqdn("@", "innotel.us")).toBe("innotel.us.");
    expect(fqdn("", "innotel.us")).toBe("innotel.us.");
  });

  it("handles already-qualified names", () => {
    expect(fqdn("www.innotel.us.", "innotel.us")).toBe("www.innotel.us.");
    expect(fqdn("innotel.us", "innotel.us")).toBe("innotel.us.");
  });

  it("handles challenge names", () => {
    expect(fqdn("_acme-challenge.innotel.us", "innotel.us")).toBe(
      "_acme-challenge.innotel.us.",
    );
  });
});

describe("parseZoneTransfer", () => {
  const axfr = `
; <<>> DiG 9.18 <<>> @192.168.1.80 innotel.us AXFR
; (1 server found)
;; global options: +cmd
innotel.us.\t300\tIN\tSOA\tns1.innotel.us. admin.innotel.us. 1 7200 3600 1209600 300
innotel.us.\t300\tIN\tNS\tns1.innotel.us.
innotel.us.\t300\tIN\tA\t192.168.1.80
www.innotel.us.\t300\tIN\tCNAME\tinnotel.us.
_acme-challenge.innotel.us.\t60\tIN\tTXT\t"abc123"
mail.innotel.us.\t300\tIN\tMX\t10 mail.innotel.us.
`;

  it("parses records and strips trailing dots and comments", () => {
    const records = parseZoneTransfer(axfr);
    expect(records).toHaveLength(6);
    expect(records[0]).toMatchObject({
      name: "innotel.us",
      type: "SOA",
      ttl: 300,
    });
    expect(records[2]).toMatchObject({
      name: "innotel.us",
      type: "A",
      value: "192.168.1.80",
    });
    expect(records[3]).toMatchObject({
      name: "www.innotel.us",
      type: "CNAME",
      value: "innotel.us.",
    });
  });

  it("unquotes TXT values", () => {
    const records = parseZoneTransfer(axfr);
    const txt = records.find((r) => r.type === "TXT")!;
    expect(txt.value).toBe("abc123");
  });

  it("ignores empty and comment lines", () => {
    expect(parseZoneTransfer(";; comment\n\ninnotel.us. 300 IN A 1.2.3.4\n")).toHaveLength(1);
  });
});
