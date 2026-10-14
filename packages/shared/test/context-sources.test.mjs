import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  factFromGhsa,
  factFromMsrc,
  factFromOsv,
  factFromRedHat,
  factFromUbuntu,
  factFromVulnrichment,
  signalsFromExploitDbCsv,
  signalsFromMetasploitIndex,
  signalsFromNucleiTree,
  vulnrichmentRawUrl
} from "../dist/index.js";

describe("context source parsers", () => {
  it("maps exploit-db codes to public pages", () => {
    const csv = [
      "id,file,description,codes",
      '16929,exploits/aix/dos/16929.rb,"Calendar overflow",CVE-2009-3699;OSVDB-58726'
    ].join("\n");
    const rows = signalsFromExploitDbCsv(csv);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].cveId, "CVE-2009-3699");
    assert.equal(rows[0].url, "https://www.exploit-db.com/exploits/16929");
    assert.equal(rows[0].signalType, "exploit_db");
    assert.equal(rows[0].title.includes("16929.rb"), false);
  });

  it("reads nuclei paths and metasploit CVE references only", () => {
    const nuclei = signalsFromNucleiTree({
      tree: [{ path: "http/cves/2024/CVE-2024-1000.yaml", type: "blob" }]
    });
    assert.equal(nuclei[0].signalType, "nuclei");
    assert.match(nuclei[0].url, /CVE-2024-1000\.yaml$/);

    const modules = signalsFromMetasploitIndex({
      "exploit/demo": {
        fullname: "exploit/demo",
        path: "/modules/exploits/demo.rb",
        description: "should not be stored",
        references: ["CVE-2024-1000", "URL-https://example.invalid/poc"]
      }
    });
    assert.equal(modules.length, 1);
    assert.equal(modules[0].title, "exploit/demo");
    assert.equal(JSON.stringify(modules).includes("should not be stored"), false);
  });

  it("keeps version and SSVC facts without advisory prose dumps", () => {
    const osv = factFromOsv({
      id: "CVE-2024-1000",
      details: "long writeup",
      affected: [{ package: { ecosystem: "npm", name: "left-pad" }, ranges: [{ events: [{ fixed: "1.2.3" }, { fixed: "abcdefabcdef" }] }] }]
    });
    assert.match(osv.detail, /left-pad: исправлено в 1\.2\.3/);
    assert.equal(osv.detail.includes("abcdef"), false);

    const ghsa = factFromGhsa([{
      ghsa_id: "GHSA-aaaa-bbbb-cccc",
      summary: "Demo",
      html_url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
      description: "do not keep",
      vulnerabilities: [{ package: { ecosystem: "npm", name: "left-pad" }, vulnerable_version_range: "< 1.2.3" }]
    }]);
    assert.equal(ghsa.detail.includes("do not keep"), false);
    assert.match(ghsa.detail, /< 1\.2\.3/);

    const redhat = factFromRedHat("CVE-2024-1000", {
      threat_severity: "Important",
      affected_release: [{ product_name: "RHEL 9", package: "left-pad-1.2.3", advisory: "RHSA-2024:1" }]
    });
    assert.match(redhat.detail, /RHSA-2024:1/);

    const ubuntu = factFromUbuntu("CVE-2024-1000", {
      packages: [{ name: "left-pad", statuses: [{ status: "released", release_codename: "noble", description: "1.2.3" }, { status: "needed", description: "pending" }] }]
    });
    assert.match(ubuntu.detail, /noble 1\.2\.3/);
    assert.equal(ubuntu.detail.includes("pending"), false);

    const msrc = factFromMsrc("CVE-2024-1000", { cveTitle: "Demo", exploited: "Yes", articles: [] });
    assert.match(msrc.detail, /эксплуатация/);

    const ssvc = factFromVulnrichment("CVE-2024-1000", {
      containers: { adp: [{ metrics: [{ other: { type: "ssvc", content: { options: [{ Exploitation: "active" }] } } }] }] }
    });
    assert.match(ssvc.detail, /Exploitation: active/);
    assert.equal(vulnrichmentRawUrl("CVE-2024-1000"), "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/2024/1xxx/CVE-2024-1000.json");
  });
});
