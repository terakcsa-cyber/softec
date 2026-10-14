import { calculateRiskScore, severityFromRisk } from "./risk";
import type {
  Patch,
  PatchState,
  Product,
  Remediation,
  RiskIndicator,
  Severity,
  Task,
  Vendor,
  Vulnerability,
  VulnerabilitySource,
  VulnStatus
} from "./types";

const TOTAL = 5175;

function mulberry32(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle<T>(items: T[], rnd: () => number) {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = Math.floor(rnd() * (i + 1));
    const tmp = items[i]!;
    items[i] = items[j]!;
    items[j] = tmp;
  }
  return items;
}

function assert(condition: boolean, message: string) {
  if (!condition) throw new Error(`VulnControl dataset: ${message}`);
}

type VendorPart = { vendor: string; vendorId: string; count: number };
type ProductSeed = {
  id: string;
  name: string;
  chartName: string;
  versions: string[];
  parts: VendorPart[];
};

const TITLES = [
  "Remote Code Execution",
  "Privilege Escalation",
  "SQL Injection",
  "Authentication Bypass",
  "Information Disclosure",
  "Cross-Site Scripting (XSS)",
  "Path Traversal",
  "Command Injection",
  "Unsafe Deserialization",
  "Server-Side Request Forgery",
  "XML External Entity",
  "Memory Corruption",
  "Buffer Overflow",
  "Use After Free",
  "Race Condition",
  "Improper Access Control",
  "Cryptographic Weakness",
  "Open Redirect"
];

const SOURCES = ["MaxPatrol VM", "Security Vision VM", "NVD / CISA KEV", "FSTEC / БДУ", "Прочие"];
const CWES = [
  "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
  "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
  "CWE-287: Improper Authentication",
  "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
  "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
  "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
];
const ASSIGNEES = ["Марина К.", "Илья С.", "Ольга Н.", "Павел Р.", "VM Team", "Аналитик смены"];

const FILLER_NAMES = [
  "Tomcat", "Jenkins", "GitLab", "Confluence", "Kubernetes", "Elasticsearch", "Redis", "RabbitMQ",
  "Django", "Spring Framework", "Node.js", "PHP", "WordPress", "Drupal", "MySQL", "MariaDB",
  "MongoDB", "Apache Kafka", "Terraform", "Ansible", "HashiCorp Vault", "Envoy", "HAProxy",
  "OpenSSH", "curl", "glibc", "Firefox", "LibreOffice", "Wireshark", "VirtualBox", "Zoom",
  "Slack", "Microsoft Exchange", "Microsoft SharePoint", "SQL Server", ".NET", "IntelliJ IDEA",
  "Rails", "Laravel", "Flask", "Express", "Angular", "Electron", "Microsoft Outlook",
  "Microsoft OneDrive", "Prometheus", "Grafana", "Filebeat", "Splunk", "FortiOS", "PAN-OS",
  "BIG-IP", "Junos OS", "VMware vCenter", "SAP NetWeaver", "IBM WebSphere", "Cisco IOS XE",
  "TeamCity", "Bitbucket", "SonarQube", "Nexus Repository", "Artifactory", "Keycloak",
  "Zabbix", "Nagios", "Bind", "Postfix", "Exim", "sudo", "libxml2", "zlib", "Thunderbird",
  "GIMP", "VLC", "Chromium", "Safari", "Azure CLI", "kubectl", "Helm", "Logstash", "Kibana",
  "QRadar", "Sentinel", "Ivanti EPMM", "MoveIt", "ScreenConnect", "PaperCut"
];

const FILLER_VENDORS = [
  "Apache", "Citrix", "PostgreSQL", "Atlassian", "F5", "Cisco", "Fortinet", "Palo Alto",
  "Juniper", "VMware", "IBM", "SAP", "Canonical", "JetBrains", "GitLab", "HashiCorp",
  "Elastic", "MongoDB", "Percona", "MariaDB", "Automattic", "Docker", "Grafana Labs",
  "Sonatype", "JFrog", "Mozilla", "Apple", "Zoom", "Slack", "Splunk", "Ivanti", "Progress",
  "PaperCut", "Zabbix", "nginx"
];

function evenCounts(total: number, size: number) {
  const counts: number[] = [];
  let left = total;
  for (let i = 0; i < size; i += 1) {
    const value = Math.floor(left / (size - i));
    counts.push(value);
    left -= value;
  }
  return counts;
}

function buildCatalog(): { products: ProductSeed[]; vendors: Vendor[] } {
  const vendorNames = [
    "Microsoft", "Oracle", "Google", "Adobe", "Red Hat", "OpenSSL Project",
    "SUSE", "Canonical", "Debian", "Fedora", "CIQ", "Alpine", "Gentoo", "Arch Linux",
    "Example Corp", "nginx", "WolfSSL", "BoringSSL", "LibreSSL",
    ...FILLER_VENDORS
  ];
  const uniqueNames = [...new Set(vendorNames)].slice(0, 50);
  const vendors: Vendor[] = uniqueNames.map((name) => ({
    id: name.toLowerCase().replace(/[^a-z0-9]+/g, "-"),
    name
  }));
  const vendorId = (name: string) => vendors.find((vendor) => vendor.name === name)?.id ?? name;

  const named: ProductSeed[] = [
    { id: "windows", name: "Windows", chartName: "Microsoft Windows", versions: ["10/11", "Server 2022", "11 24H2"], parts: [{ vendor: "Microsoft", vendorId: vendorId("Microsoft"), count: 842 }] },
    { id: "kernel", name: "Linux Kernel", chartName: "Linux Kernel", versions: ["6.6.x", "6.8.x", "5.15.x"], parts: [
      { vendor: "SUSE", vendorId: vendorId("SUSE"), count: 80 },
      { vendor: "Canonical", vendorId: vendorId("Canonical"), count: 80 },
      { vendor: "Debian", vendorId: vendorId("Debian"), count: 78 },
      { vendor: "Fedora", vendorId: vendorId("Fedora"), count: 78 },
      { vendor: "CIQ", vendorId: vendorId("CIQ"), count: 76 },
      { vendor: "Alpine", vendorId: vendorId("Alpine"), count: 76 },
      { vendor: "Gentoo", vendorId: vendorId("Gentoo"), count: 72 },
      { vendor: "Arch Linux", vendorId: vendorId("Arch Linux"), count: 72 }
    ] },
    { id: "chrome", name: "Google Chrome", chartName: "Google Chrome", versions: ["120.x", "121.x", "122.x"], parts: [{ vendor: "Google", vendorId: vendorId("Google"), count: 421 }] },
    { id: "acrobat", name: "Adobe Acrobat", chartName: "Adobe Acrobat", versions: ["2024.x", "2023.x", "2020.x"], parts: [{ vendor: "Adobe", vendorId: vendorId("Adobe"), count: 356 }] },
    { id: "openssl", name: "OpenSSL", chartName: "OpenSSL", versions: ["3.0.x", "3.2.x", "1.1.1"], parts: [
      { vendor: "OpenSSL Project", vendorId: vendorId("OpenSSL Project"), count: 200 },
      { vendor: "WolfSSL", vendorId: vendorId("WolfSSL"), count: 34 },
      { vendor: "BoringSSL", vendorId: vendorId("BoringSSL"), count: 32 },
      { vendor: "LibreSSL", vendorId: vendorId("LibreSSL"), count: 32 }
    ] },
    { id: "m365", name: "Microsoft 365", chartName: "Microsoft 365", versions: ["Current", "Semi-Annual"], parts: [{ vendor: "Microsoft", vendorId: vendorId("Microsoft"), count: 200 }] },
    { id: "edge", name: "Microsoft Edge", chartName: "Microsoft Edge", versions: ["122.x", "121.x"], parts: [{ vendor: "Microsoft", vendorId: vendorId("Microsoft"), count: 204 }] },
    { id: "oracledb", name: "Oracle Database", chartName: "Oracle Database", versions: ["19c", "21c", "23ai"], parts: [{ vendor: "Oracle", vendorId: vendorId("Oracle"), count: 250 }] },
    { id: "java", name: "Oracle Java", chartName: "Oracle Java", versions: ["17.x", "21.x", "8u"], parts: [{ vendor: "Oracle", vendorId: vendorId("Oracle"), count: 200 }] },
    { id: "weblogic", name: "Oracle WebLogic", chartName: "Oracle WebLogic", versions: ["14.1.x", "12.2.x"], parts: [{ vendor: "Oracle", vendorId: vendorId("Oracle"), count: 192 }] },
    { id: "rhel", name: "Red Hat Enterprise Linux", chartName: "Red Hat Enterprise Linux", versions: ["9.x", "8.x"], parts: [{ vendor: "Red Hat", vendorId: vendorId("Red Hat"), count: 180 }] },
    { id: "openshift", name: "Red Hat OpenShift", chartName: "Red Hat OpenShift", versions: ["4.14", "4.15", "4.16"], parts: [{ vendor: "Red Hat", vendorId: vendorId("Red Hat"), count: 118 }] },
    { id: "example", name: "Example Service", chartName: "Example Service", versions: ["4.2.x", "4.1.x", "4.0.x"], parts: [{ vendor: "Example Corp", vendorId: vendorId("Example Corp"), count: 24 }] },
    { id: "apache-http", name: "Apache HTTP Server", chartName: "Apache HTTP Server", versions: ["2.4.x", "2.2.x"], parts: [{ vendor: "Apache", vendorId: vendorId("Apache"), count: 40 }] },
    { id: "citrix", name: "Citrix ADC", chartName: "Citrix ADC", versions: ["13.x", "14.x"], parts: [{ vendor: "Citrix", vendorId: vendorId("Citrix"), count: 28 }] },
    { id: "postgresql", name: "PostgreSQL", chartName: "PostgreSQL", versions: ["15.x", "16.x", "14.x"], parts: [{ vendor: "PostgreSQL", vendorId: vendorId("PostgreSQL"), count: 36 }] },
    { id: "jira", name: "Jira Software", chartName: "Jira Software", versions: ["9.x", "10.x"], parts: [{ vendor: "Atlassian", vendorId: vendorId("Atlassian"), count: 32 }] },
    { id: "nginx", name: "nginx", chartName: "nginx", versions: ["1.20.x", "1.24.x", "1.26.x"], parts: [{ vendor: "nginx", vendorId: vendorId("nginx"), count: 30 }] }
  ];

  const fillerCounts = evenCounts(1112, 82);
  const filler: ProductSeed[] = FILLER_NAMES.slice(0, 82).map((name, index) => {
    const vendor = FILLER_VENDORS[index % FILLER_VENDORS.length]!;
    return {
      id: `filler-${index}`,
      name,
      chartName: name,
      versions: ["1.x", "2.x", "3.x"],
      parts: [{ vendor, vendorId: vendorId(vendor), count: fillerCounts[index]! }]
    };
  });

  return { products: [...named, ...filler], vendors };
}

const SHOWCASES: Array<Partial<Vulnerability> & { cve: string; product: string; severity: Severity }> = [
  {
    cve: "CVE-2026-42897",
    title: "Remote Code Execution in Example Service",
    riskScore: 9.8,
    cvss: 9.8,
    epss: 0.87,
    severity: "critical",
    kev: true,
    exploitAvailable: true,
    pocAvailable: true,
    patchState: "available",
    product: "Example Service",
    version: "4.2.x",
    vendor: "Example Corp",
    status: "open",
    taskId: "VM-12456",
    discoveredAt: "2026-10-10T23:00:00.000Z",
    updatedAt: "2026-10-10T23:00:00.000Z",
    cwe: "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    source: "MaxPatrol VM",
    fixedVersion: "4.2.7",
    affectedVersions: ["4.0.x", "4.1.x", "4.2.x"],
    description: "Уязвимость позволяет удалённое выполнение произвольного кода в Example Service при обработке специально сформированного запроса. Эксплуатация возможна без аутентификации."
  },
  {
    cve: "CVE-2026-41012",
    title: "Privilege Escalation in Windows Kernel",
    riskScore: 9.1,
    cvss: 8.8,
    epss: 0.64,
    severity: "critical",
    kev: false,
    exploitAvailable: true,
    patchState: "available",
    product: "Windows",
    version: "10/11",
    vendor: "Microsoft",
    status: "in_progress",
    taskId: "VM-12451",
    discoveredAt: "2026-10-10T22:00:00.000Z",
    fixedVersion: "KB504012",
    affectedVersions: ["10/11", "Server 2022"],
    description: "Локальный пользователь может повысить привилегии через ошибку в ядре Windows."
  },
  {
    cve: "CVE-2026-39544",
    title: "SQL Injection in Web Application",
    riskScore: 8.8,
    cvss: 8.2,
    epss: 0.51,
    severity: "high",
    kev: false,
    exploitAvailable: true,
    patchState: "available",
    product: "Apache HTTP Server",
    version: "2.4.x",
    vendor: "Apache",
    status: "open",
    taskId: "VM-12432",
    discoveredAt: "2026-10-10T21:00:00.000Z",
    fixedVersion: "2.4.62",
    affectedVersions: ["2.4.x"],
    description: "Модуль приложения некорректно экранирует параметр фильтра и позволяет внедрить SQL."
  },
  {
    cve: "CVE-2026-38109",
    title: "Authentication Bypass in VPN Gateway",
    riskScore: 8.1,
    cvss: 8.6,
    epss: 0.43,
    severity: "high",
    kev: true,
    exploitAvailable: true,
    patchState: "available",
    product: "Citrix ADC",
    version: "13.x",
    vendor: "Citrix",
    status: "in_progress",
    taskId: "VM-12428",
    discoveredAt: "2026-10-10T20:00:00.000Z",
    fixedVersion: "13.1-53.17",
    affectedVersions: ["13.x", "14.x"],
    description: "Ошибка проверки сессии на VPN-шлюзе позволяет обойти аутентификацию."
  },
  {
    cve: "CVE-2026-37211",
    title: "Information Disclosure in File Service",
    riskScore: 6.5,
    cvss: 5.9,
    epss: 0.28,
    severity: "medium",
    kev: false,
    exploitAvailable: false,
    patchState: "available",
    product: "PostgreSQL",
    version: "15.x",
    vendor: "PostgreSQL",
    status: "open",
    taskId: "VM-12411",
    discoveredAt: "2026-10-10T19:00:00.000Z",
    fixedVersion: "15.8",
    affectedVersions: ["15.x", "14.x"],
    description: "Файловый сервис отдаёт метаданные чужих объектов при определённом порядке запросов."
  },
  {
    cve: "CVE-2026-36890",
    title: "Cross-Site Scripting (XSS) in Portal",
    riskScore: 7.8,
    cvss: 6.4,
    epss: 0.35,
    severity: "high",
    kev: false,
    exploitAvailable: false,
    patchState: "available",
    product: "Jira Software",
    version: "9.x",
    vendor: "Atlassian",
    status: "in_progress",
    taskId: "VM-12409",
    discoveredAt: "2026-10-10T18:00:00.000Z",
    fixedVersion: "9.12.12",
    affectedVersions: ["9.x"],
    description: "Поле портала отражает ввод без кодирования и позволяет выполнить скрипт в сессии пользователя."
  },
  {
    cve: "CVE-2026-35122",
    title: "Outdated OpenSSL Version",
    riskScore: 6.1,
    cvss: 5.3,
    epss: 0.14,
    severity: "medium",
    kev: false,
    exploitAvailable: false,
    patchState: "available",
    product: "OpenSSL",
    version: "3.0.x",
    vendor: "OpenSSL Project",
    status: "open",
    taskId: "VM-12398",
    discoveredAt: "2026-10-10T17:00:00.000Z",
    fixedVersion: "3.0.15",
    affectedVersions: ["3.0.x"],
    description: "Используемая ветка OpenSSL содержит исправленные в более новых сборках дефекты разбора сертификатов."
  },
  {
    cve: "CVE-2026-34015",
    title: "Deprecated TLS Version Support",
    riskScore: 4.3,
    cvss: 3.7,
    epss: 0.07,
    severity: "low",
    kev: false,
    exploitAvailable: false,
    patchState: "available",
    product: "nginx",
    version: "1.20.x",
    vendor: "nginx",
    status: "resolved",
    taskId: "VM-12387",
    discoveredAt: "2026-10-10T16:00:00.000Z",
    fixedVersion: "1.26.2",
    affectedVersions: ["1.20.x"],
    description: "Конфигурация по-прежнему принимает устаревшие версии TLS. Исправление уже выпущено и задача закрыта."
  }
];

const CHART_BUCKETS: Array<{ date: string; counts: Record<Severity, number> }> = [
  { date: "2026-09-10", counts: { critical: 8, high: 18, medium: 30, low: 48 } },
  { date: "2026-09-15", counts: { critical: 12, high: 24, medium: 42, low: 70 } },
  { date: "2026-09-20", counts: { critical: 10, high: 28, medium: 55, low: 95 } },
  { date: "2026-09-25", counts: { critical: 14, high: 22, medium: 48, low: 80 } },
  { date: "2026-09-30", counts: { critical: 11, high: 35, medium: 60, low: 120 } },
  { date: "2026-10-05", counts: { critical: 18, high: 40, medium: 75, low: 175 } },
  { date: "2026-10-10", counts: { critical: 12, high: 30, medium: 52, low: 110 } }
];

function buildDataset() {
  const rnd = mulberry32(20261012);
  const { products: seeds, vendors } = buildCatalog();
  const slots: Array<{ product: ProductSeed; vendor: string; vendorId: string }> = [];
  for (const product of seeds) {
    for (const part of product.parts) {
      for (let i = 0; i < part.count; i += 1) slots.push({ product, vendor: part.vendor, vendorId: part.vendorId });
    }
  }
  assert(slots.length === TOTAL, `slots ${slots.length}`);
  shuffle(slots, rnd);

  const severities = shuffle<Severity>([
    ...Array<Severity>(128).fill("critical"),
    ...Array<Severity>(342).fill("high"),
    ...Array<Severity>(1284).fill("medium"),
    ...Array<Severity>(3421).fill("low")
  ], rnd);
  const statuses = shuffle<VulnStatus>([
    ...Array<VulnStatus>(1921).fill("resolved"),
    ...Array<VulnStatus>(1768).fill("in_progress"),
    ...Array<VulnStatus>(873).fill("open"),
    ...Array<VulnStatus>(443).fill("accepted_risk"),
    ...Array<VulnStatus>(170).fill("overdue")
  ], rnd);
  const patches = shuffle<PatchState>([
    ...Array<PatchState>(3921).fill("available"),
    ...Array<PatchState>(412).fill("none"),
    ...Array<PatchState>(638).fill("analysis"),
    ...Array<PatchState>(204).fill("na")
  ], rnd);

  const criticalIdx = severities.map((severity, index) => (severity === "critical" ? index : -1)).filter((index) => index >= 0);
  const highIdx = severities.map((severity, index) => (severity === "high" ? index : -1)).filter((index) => index >= 0);
  shuffle(criticalIdx, rnd);
  shuffle(highIdx, rnd);
  const kevSet = new Set(criticalIdx.slice(0, 47));
  const epssSet = new Set([...criticalIdx.slice(0, 128), ...highIdx.slice(0, 8)]);
  const exploitPool = shuffle([...criticalIdx, ...highIdx, ...severities.map((_, index) => index).filter((index) => severities[index] === "medium")], rnd);
  const exploitSet = new Set(exploitPool.slice(0, 289));

  const vulns: Vulnerability[] = slots.map((slot, index) => {
    const severity = severities[index]!;
    const kev = kevSet.has(index);
    const exploitAvailable = exploitSet.has(index);
    const patchState = patches[index]!;
    const patchAvailable = patchState === "available";
    const epss = epssSet.has(index) ? Math.round((0.7 + rnd() * 0.29) * 100) / 100 : Math.round(rnd() * 69) / 100;
    let cvss = severity === "critical" ? 8.4 : severity === "high" ? 6.6 : severity === "medium" ? 4.8 : 2.2;
    let riskScore = calculateRiskScore({ cvss, epss, kev, exploitAvailable, patchAvailable });
    for (let step = 0; step < 30 && severityFromRisk(riskScore) !== severity; step += 1) {
      cvss = severityFromRisk(riskScore) === "low" || riskScore < bandFloor(severity) ? cvss + 0.3 : cvss - 0.3;
      cvss = Math.round(Math.min(10, Math.max(0.1, cvss)) * 10) / 10;
      riskScore = calculateRiskScore({ cvss, epss, kev, exploitAvailable, patchAvailable });
    }
    if (severityFromRisk(riskScore) !== severity) {
      riskScore = bandFloor(severity);
    }
    const version = slot.product.versions[Math.floor(rnd() * slot.product.versions.length)]!;
    const cveNum = 11000 + index;
    return {
      id: `cve-2026-${cveNum}`,
      cve: `CVE-2026-${cveNum}`,
      title: `${TITLES[index % TITLES.length]} in ${slot.product.name}`,
      riskScore,
      cvss,
      epss,
      severity,
      kev,
      exploitAvailable,
      pocAvailable: exploitAvailable || index % 11 === 0,
      patchAvailable,
      patchState,
      product: slot.product.name,
      productId: slot.product.id,
      version,
      vendor: slot.vendor,
      vendorId: slot.vendorId,
      source: SOURCES[index % SOURCES.length]!,
      status: statuses[index]!,
      discoveredAt: "2025-06-15T00:00:00.000Z",
      updatedAt: "2025-06-15T00:00:00.000Z",
      cwe: CWES[index % CWES.length]!,
      attention: false,
      exploitTrend: false,
      criticalProduct: false,
      fixedVersion: version.replace("x", "9"),
      affectedVersions: slot.product.versions,
      description: `${TITLES[index % TITLES.length]} затрагивает ${slot.product.name} ${version}. Оценка VulnControl учитывает CVSS, EPSS, наличие KEV, эксплойта и исправления.`
    };
  });

  for (const spec of SHOWCASES) {
    let index = vulns.findIndex((vuln) => !vuln.cve.startsWith("CVE-2026-4") && vuln.product === spec.product && vuln.severity === spec.severity);
    if (index < 0) {
      const productIndex = vulns.findIndex((vuln) => vuln.product === spec.product && !SHOWCASES.some((item) => item.cve === vuln.cve));
      const severityIndex = vulns.findIndex((vuln) => vuln.severity === spec.severity && vuln.product !== spec.product && !SHOWCASES.some((item) => item.cve === vuln.cve));
      assert(productIndex >= 0 && severityIndex >= 0, `showcase slot ${spec.cve}`);
      const severity = vulns[productIndex]!.severity;
      const riskScore = vulns[productIndex]!.riskScore;
      const cvss = vulns[productIndex]!.cvss;
      vulns[productIndex]!.severity = vulns[severityIndex]!.severity;
      vulns[productIndex]!.riskScore = vulns[severityIndex]!.riskScore;
      vulns[productIndex]!.cvss = vulns[severityIndex]!.cvss;
      vulns[severityIndex]!.severity = severity;
      vulns[severityIndex]!.riskScore = riskScore;
      vulns[severityIndex]!.cvss = cvss;
      index = productIndex;
    }
    const current = vulns[index]!;
    vulns[index] = {
      ...current,
      ...spec,
      id: spec.cve.toLowerCase(),
      patchAvailable: spec.patchState === "available",
      productId: current.productId,
      vendorId: current.vendorId,
      source: spec.source ?? current.source,
      attention: false,
      exploitTrend: false,
      criticalProduct: false,
      affectedVersions: spec.affectedVersions ?? current.affectedVersions,
      description: spec.description ?? current.description,
      fixedVersion: spec.fixedVersion ?? current.fixedVersion
    };
  }

  const pinned = new Set(SHOWCASES.map((spec) => spec.cve));
  rebalance(vulns, pinned);
  for (const bucket of CHART_BUCKETS) {
    (Object.keys(bucket.counts) as Severity[]).forEach((severity) => {
      let left = bucket.counts[severity];
      for (const vuln of vulns) {
        if (left <= 0) break;
        if (vuln.severity !== severity || pinned.has(vuln.cve) || vuln.discoveredAt !== "2025-06-15T00:00:00.000Z") continue;
        vuln.discoveredAt = `${bucket.date}T09:00:00.000Z`;
        left -= 1;
      }
    });
  }
  for (const vuln of vulns) {
    if (vuln.discoveredAt !== "2025-06-15T00:00:00.000Z") continue;
    const day = Math.floor(rnd() * 400);
    const date = new Date(Date.UTC(2025, 0, 1));
    date.setUTCDate(date.getUTCDate() + day);
    vuln.discoveredAt = date.toISOString();
  }
  for (const vuln of vulns) {
    if (!vuln.updatedAt || vuln.updatedAt === "2025-06-15T00:00:00.000Z") vuln.updatedAt = vuln.discoveredAt;
  }

  const attention = new Set<number>();
  vulns.forEach((vuln, index) => {
    if (vuln.severity === "critical" || vuln.kev || vuln.status === "overdue") attention.add(index);
  });
  for (let index = 0; attention.size < 897 && index < vulns.length; index += 1) {
    if (vulns[index]!.severity === "high" || vulns[index]!.epss >= 0.7) attention.add(index);
  }
  for (let index = 0; attention.size < 897 && index < vulns.length; index += 1) attention.add(index);
  if (attention.size > 897) {
    for (const index of [...attention]) {
      if (attention.size <= 897) break;
      const vuln = vulns[index]!;
      if (vuln.severity !== "critical" && !vuln.kev && vuln.status !== "overdue") attention.delete(index);
    }
  }
  assert(attention.size === 897, `attention ${attention.size}`);
  attention.forEach((index) => {
    vulns[index]!.attention = true;
  });

  let trendLeft = 336;
  let criticalLeft = 178;
  for (const vuln of vulns) {
    if (trendLeft > 0 && (vuln.exploitAvailable || vuln.kev || vuln.epss >= 0.5)) {
      vuln.exploitTrend = true;
      trendLeft -= 1;
    }
    if (criticalLeft > 0 && (vuln.severity === "critical" || vuln.severity === "high")) {
      vuln.criticalProduct = true;
      criticalLeft -= 1;
    }
  }
  assert(trendLeft === 0 && criticalLeft === 0, "trend flags");

  const products: Product[] = seeds.map((seed) => ({
    id: seed.id,
    name: seed.name,
    chartName: seed.chartName,
    vendor: seed.parts[0]!.vendor,
    versions: seed.versions,
    vulnerabilityCount: seed.parts.reduce((sum, part) => sum + part.count, 0)
  }));

  const showcaseTasks: Task[] = SHOWCASES.map((spec) => ({
    id: spec.taskId!,
    vulnerabilityId: spec.cve.toLowerCase(),
    cve: spec.cve,
    title: spec.title!,
    product: spec.product,
    status: spec.status!,
    assignee: spec.cve === "CVE-2026-42897" ? "Security Team" : "VM Team",
    dueAt: spec.cve === "CVE-2026-42897" ? "2026-10-12" : spec.status === "overdue" ? "2026-10-01" : "2026-10-20"
  }));
  const extraTasks: Task[] = [];
  for (const vuln of vulns) {
    if (extraTasks.length >= 212) break;
    if (pinned.has(vuln.cve) || vuln.taskId) continue;
    const id = `VM-${12000 + extraTasks.length}`;
    vuln.taskId = id;
    extraTasks.push({
      id,
      vulnerabilityId: vuln.id,
      cve: vuln.cve,
      title: vuln.title,
      product: vuln.product,
      status: vuln.status,
      assignee: ASSIGNEES[extraTasks.length % ASSIGNEES.length]!,
      dueAt: vuln.status === "overdue" ? "2026-09-28" : "2026-10-24"
    });
  }
  const tasks = [...showcaseTasks, ...extraTasks];

  const patchMap = new Map<string, Patch>();
  for (const vuln of vulns) {
    if (vuln.patchState !== "available") continue;
    const key = `${vuln.productId}:${vuln.fixedVersion}`;
    const existing = patchMap.get(key);
    if (existing) existing.cveCount += 1;
    else {
      patchMap.set(key, {
        id: `patch-${patchMap.size + 1}`,
        productId: vuln.productId,
        product: vuln.product,
        vendor: vuln.vendor,
        version: vuln.fixedVersion,
        cveCount: 1,
        available: true
      });
    }
  }
  const patchesOut = [...patchMap.values()];

  const remediations: Remediation[] = vulns.map((vuln) => {
    const total = 20 + (vuln.cve.charCodeAt(vuln.cve.length - 1) % 30);
    const done = vuln.status === "resolved" ? total : vuln.status === "in_progress" ? Math.max(1, Math.round(total * 0.35)) : vuln.cve === "CVE-2026-42897" ? 12 : 0;
    return {
      vulnerabilityId: vuln.id,
      recommendation: vuln.patchAvailable
        ? `Обновить ${vuln.product} до версии ${vuln.fixedVersion}.`
        : `Исправления для ${vuln.product} нет. Ограничить доступ к уязвимому компоненту и отслеживать vendor advisory.`,
      fixedVersion: vuln.fixedVersion,
      progressDone: vuln.cve === "CVE-2026-42897" ? 12 : done,
      progressTotal: vuln.cve === "CVE-2026-42897" ? 34 : total
    };
  });

  const indicators: RiskIndicator[] = [
    { id: "kev", label: "CISA KEV (эксплуатируемые)", value: 47, delta: 24, kind: "kev" },
    { id: "epss", label: "Высокий EPSS (>0.7)", value: 136, delta: 18, kind: "epss" },
    { id: "exploit", label: "Доступен PoC / Exploit", value: 289, delta: 11, kind: "exploit" },
    { id: "nopatch", label: "Нет исправления", value: 412, delta: 7, kind: "nopatch" },
    { id: "trend", label: "Тренд роста эксплуатации", value: 336, delta: 15, kind: "trend" },
    { id: "crit-products", label: "Критичные продукты", value: 178, delta: 9, kind: "criticalProducts" }
  ];
  const byProduct = new Map<string, number>();
  for (const vuln of vulns) {
    if (vuln.severity === "critical") byProduct.set(vuln.product, (byProduct.get(vuln.product) ?? 0) + 1);
  }
  const extraIndicators: RiskIndicator[] = [...byProduct.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([product, value]) => ({
      id: `product-${product}`,
      label: product,
      value,
      delta: 4 + (product.length % 12),
      kind: "product" as const,
      product
    }));
  const byVendor = new Map<string, number>();
  for (const vuln of vulns) byVendor.set(vuln.vendor, (byVendor.get(vuln.vendor) ?? 0) + 1);
  for (const [vendor, value] of [...byVendor.entries()].sort((a, b) => b[1] - a[1])) {
    if (indicators.length + extraIndicators.length >= 50) break;
    extraIndicators.push({ id: `vendor-${vendor}`, label: vendor, value, delta: 6, kind: "product" });
  }

  assignSources(vulns);
  const sources: VulnerabilitySource[] = [
    { id: "maxpatrol", name: "MaxPatrol VM", coverage: 62.4 },
    { id: "security-vision", name: "Security Vision VM", coverage: 24.1 },
    { id: "nvd", name: "NVD / CISA KEV", coverage: 7.8 },
    { id: "fstec", name: "FSTEC / БДУ", coverage: 4.2 },
    { id: "other", name: "Прочие", coverage: 1.5 }
  ];

  assert(vulns.filter((vuln) => vuln.severity === "critical").length === 128, "critical");
  assert(vulns.filter((vuln) => vuln.severity === "high").length === 342, "high");
  assert(vulns.filter((vuln) => vuln.severity === "medium").length === 1284, "medium");
  assert(vulns.filter((vuln) => vuln.severity === "low").length === 3421, "low");
  assert(vulns.filter((vuln) => vuln.kev).length === 47, "kev");
  assert(vulns.filter((vuln) => vuln.epss >= 0.7).length === 136, "epss");
  assert(vulns.filter((vuln) => vuln.patchState === "none").length === 412, "nopatch");
  assert(vulns.filter((vuln) => vuln.status === "overdue").length === 170, "overdue");
  assert(products.length === 100, `products ${products.length}`);
  assert(vendors.length === 50, `vendors ${vendors.length}`);
  assert(patchesOut.length >= 100, "patches");
  assert(tasks.length >= 200, "tasks");

  return {
    vulnerabilities: vulns,
    products,
    vendors,
    patches: patchesOut,
    tasks,
    remediations,
    indicators: [...indicators, ...extraIndicators],
    sources
  };
}

function assignSources(vulns: Vulnerability[]) {
  const quotas: Array<[string, number]> = [
    ["MaxPatrol VM", 3229],
    ["Security Vision VM", 1247],
    ["NVD / CISA KEV", 404],
    ["FSTEC / БДУ", 217],
    ["Прочие", 78]
  ];
  const lead = vulns.find((vuln) => vuln.cve === "CVE-2026-42897");
  if (lead) {
    lead.source = "MaxPatrol VM";
    quotas[0] = ["MaxPatrol VM", quotas[0]![1] - 1];
  }
  let index = 0;
  let left = quotas[0]![1];
  for (const vuln of vulns) {
    if (vuln.cve === "CVE-2026-42897") continue;
    while (left <= 0 && index < quotas.length - 1) {
      index += 1;
      left = quotas[index]![1];
    }
    vuln.source = quotas[index]![0];
    left -= 1;
  }
  const tally = vulns.reduce<Record<string, number>>((map, vuln) => {
    map[vuln.source] = (map[vuln.source] ?? 0) + 1;
    return map;
  }, {});
  assert(tally["MaxPatrol VM"] === 3229, "source maxpatrol");
  assert(tally["Security Vision VM"] === 1247, "source sv");
  assert(tally["NVD / CISA KEV"] === 404, "source nvd");
  assert(tally["FSTEC / БДУ"] === 217, "source fstec");
  assert(tally["Прочие"] === 78, "source other");
}

function refillField<T extends string>(
  vulns: Vulnerability[],
  pinned: Set<string>,
  key: "severity" | "status" | "patchState",
  quotas: Record<string, number>
) {
  const remaining: Record<string, number> = { ...quotas };
  for (const vuln of vulns) {
    if (!pinned.has(vuln.cve)) continue;
    remaining[String(vuln[key])] = (remaining[String(vuln[key])] ?? 0) - 1;
  }
  const pool = vulns.filter((vuln) => !pinned.has(vuln.cve));
  let cursor = 0;
  for (const [value, count] of Object.entries(remaining)) {
    assert(count >= 0, `${key} ${value} oversubscribed`);
    for (let n = 0; n < count; n += 1) {
      const vuln = pool[cursor];
      if (!vuln) throw new Error(`VulnControl dataset: ${key} pool`);
      if (key === "patchState") {
        vuln.patchState = value as PatchState;
        vuln.patchAvailable = value === "available";
      } else if (key === "severity") {
        const severity = value as Severity;
        vuln.severity = severity;
        const floor = bandFloor(severity);
        const ceil = severity === "critical" ? 10 : severity === "high" ? 8.9 : severity === "medium" ? 6.9 : 4.9;
        const spread = (Number(vuln.cve.replace(/\D/g, "").slice(-3)) % 100) / 100;
        vuln.riskScore = Math.round((floor + spread * (ceil - floor)) * 10) / 10;
      } else {
        vuln.status = value as VulnStatus;
      }
      cursor += 1;
    }
  }
}

function rebalance(vulns: Vulnerability[], pinned: Set<string>) {
  refillField(vulns, pinned, "severity", { critical: 128, high: 342, medium: 1284, low: 3421 });
  refillField(vulns, pinned, "status", { resolved: 1921, in_progress: 1768, open: 873, accepted_risk: 443, overdue: 170 });
  refillField(vulns, pinned, "patchState", { available: 3921, none: 412, analysis: 638, na: 204 });
  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  for (const vuln of vulns) {
    if (!pinned.has(vuln.cve)) vuln.kev = false;
  }
  const kevPool = vulns
    .filter((vuln) => !pinned.has(vuln.cve) && !vuln.kev)
    .sort((a, b) => rank[a.severity] - rank[b.severity]);
  let kevLeft = 47 - vulns.filter((vuln) => vuln.kev).length;
  for (const vuln of kevPool) {
    if (kevLeft <= 0) break;
    vuln.kev = true;
    kevLeft -= 1;
  }
  for (const vuln of vulns) {
    if (pinned.has(vuln.cve)) continue;
    if (vuln.epss >= 0.7) vuln.epss = 0.22;
  }
  const epssPool = vulns
    .filter((vuln) => !pinned.has(vuln.cve))
    .sort((a, b) => rank[a.severity] - rank[b.severity] || (b.kev ? 1 : 0) - (a.kev ? 1 : 0));
  let epssLeft = 136 - vulns.filter((vuln) => vuln.epss >= 0.7).length;
  for (const vuln of epssPool) {
    if (epssLeft <= 0) break;
    vuln.epss = 0.74 + (vuln.cve.charCodeAt(vuln.cve.length - 1) % 20) / 100;
    epssLeft -= 1;
  }
}

function bandFloor(severity: Severity) {
  if (severity === "critical") return 9;
  if (severity === "high") return 7;
  if (severity === "medium") return 5;
  return 1;
}

export const VC_DATA = buildDataset();

export function remediationFor(id: string) {
  return VC_DATA.remediations.find((item) => item.vulnerabilityId === id) ?? null;
}
