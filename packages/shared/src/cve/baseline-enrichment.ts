import { augmentEnrichmentWithNvdFixes } from "./nvd-fix-signals.js";

type JsonObj = Record<string, unknown>;

function asObj(v: unknown): JsonObj | null {
  return v != null && typeof v === "object" && !Array.isArray(v) ? (v as JsonObj) : null;
}

function str(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

function pickDescriptionFromList(descs: unknown): string {
  if (!Array.isArray(descs) || descs.length === 0) return "";
  let en = "";
  let any = "";
  for (const d of descs) {
    const o = asObj(d);
    const val = str(o?.value).replace(/\s+/g, " ").trim();
    if (!val) continue;
    if (!any) any = val;
    const lang = str(o?.lang).toLowerCase();
    if (lang === "ru" || lang.startsWith("ru-")) return val;
    if (!en && (lang === "en" || lang.startsWith("en-") || !lang)) en = val;
  }
  return en || any;
}

function firstDescription(raw: JsonObj): string {
  const fromTop = pickDescriptionFromList(raw.descriptions);
  if (fromTop) return fromTop;
  const leg = asObj(raw.cve);
  const fromLegacy = pickDescriptionFromList(leg?.descriptions);
  if (fromLegacy) return fromLegacy;
  const vulns = raw.vulnerabilities;
  if (Array.isArray(vulns) && vulns[0]) {
    const cve = asObj(asObj(vulns[0])?.cve);
    const fromVuln = pickDescriptionFromList(cve?.descriptions);
    if (fromVuln) return fromVuln;
  }
  return "";
}

function extractCweLabels(raw: JsonObj): string[] {
  const out: string[] = [];
  const sources: unknown[] = [];
  if (Array.isArray(raw.weaknesses)) sources.push(...raw.weaknesses);
  const nested = asObj(raw.cve);
  if (Array.isArray(nested?.weaknesses)) sources.push(...nested.weaknesses);
  const vulns = raw.vulnerabilities;
  if (Array.isArray(vulns) && vulns[0]) {
    const cve = asObj(asObj(vulns[0])?.cve);
    if (Array.isArray(cve?.weaknesses)) sources.push(...cve.weaknesses);
  }

  for (const w of sources) {
    const wo = asObj(w);
    const descs = wo?.description;
    if (Array.isArray(descs)) {
      for (const d of descs) {
        const val = str(asObj(d)?.value);
        if (val && !out.includes(val)) out.push(val);
      }
    }
    const type = str(wo?.type);
    if (/^CWE-\d+$/i.test(type) && !out.some((x) => x.toUpperCase() === type.toUpperCase())) {
      out.push(type.toUpperCase());
    }
  }
  return out;
}

type CweInfo = { en: string; ru: string; impact: string; remediation: string };

const CWE_INFO: Record<string, CweInfo> = {
  "CWE-20": {
    en: "Improper Input Validation",
    ru: "некорректная проверка входных данных",
    impact: "передача специально сформированных данных может привести к обходу проверок или сбою логики обработки",
    remediation: "Усилить валидацию входных данных и установить исправления вендора."
  },
  "CWE-22": {
    en: "Path Traversal",
    ru: "обход пути к файлам",
    impact: "атакующий может обратиться к файлам за пределами разрешённого каталога",
    remediation: "Обновить компонент и ограничить доступ к файловым путям через allowlist/нормализацию."
  },
  "CWE-78": {
    en: "OS Command Injection",
    ru: "инъекция команд ОС",
    impact: "возможен запуск команд ОС от имени уязвимого сервиса",
    remediation: "Установить патч и исключить передачу пользовательского ввода в shell-команды."
  },
  "CWE-79": {
    en: "Cross-site Scripting (XSS)",
    ru: "межсайтовый скриптинг (XSS)",
    impact: "возможен запуск JavaScript в браузере пользователя и кража сессионных данных",
    remediation: "Обновить компонент, включить контекстное экранирование вывода и CSP."
  },
  "CWE-89": {
    en: "SQL Injection",
    ru: "SQL-инъекция",
    impact: "возможен доступ к данным БД или изменение запросов через пользовательский ввод",
    remediation: "Установить исправления и использовать параметризованные SQL-запросы."
  },
  "CWE-94": {
    en: "Code Injection",
    ru: "инъекция кода",
    impact: "возможно выполнение произвольного кода в контексте приложения",
    remediation: "Обновить компонент и запретить интерпретацию пользовательских данных как кода."
  },
  "CWE-119": {
    en: "Memory Buffer Overflow",
    ru: "ошибка работы с буфером памяти",
    impact: "возможны повреждение памяти, отказ в обслуживании или выполнение кода",
    remediation: "Установить исправленную версию и включить доступные memory-safety mitigations."
  },
  "CWE-120": {
    en: "Buffer Copy without Size Check",
    ru: "копирование буфера без проверки размера",
    impact: "переполнение буфера может привести к аварийному завершению или выполнению кода",
    remediation: "Обновить компонент и использовать безопасные функции копирования с контролем границ."
  },
  "CWE-125": {
    en: "Out-of-bounds Read",
    ru: "чтение за пределами буфера",
    impact: "возможны утечка памяти процесса или отказ в обслуживании",
    remediation: "Установить патч и ограничить обработку недоверенных входных данных."
  },
  "CWE-190": {
    en: "Integer Overflow",
    ru: "целочисленное переполнение",
    impact: "ошибка расчёта размера/индекса может привести к повреждению памяти или обходу проверок",
    remediation: "Установить исправления и проверять диапазоны числовых значений."
  },
  "CWE-200": {
    en: "Information Exposure",
    ru: "раскрытие информации",
    impact: "атакующий может получить чувствительные данные или служебную информацию",
    remediation: "Обновить компонент и ограничить выдачу диагностических/служебных данных."
  },
  "CWE-287": {
    en: "Improper Authentication",
    ru: "ошибка аутентификации",
    impact: "возможен вход или выполнение действий без корректной проверки личности",
    remediation: "Установить патч и проверить настройки аутентификации/сессий."
  },
  "CWE-306": {
    en: "Missing Authentication",
    ru: "отсутствие обязательной аутентификации",
    impact: "функция может быть доступна без входа в систему",
    remediation: "Закрыть endpoint аутентификацией и установить исправленную версию."
  },
  "CWE-352": {
    en: "CSRF",
    ru: "межсайтовая подделка запроса (CSRF)",
    impact: "пользователя можно вынудить выполнить нежелательное действие в приложении",
    remediation: "Включить CSRF-токены, SameSite cookies и обновить уязвимый компонент."
  },
  "CWE-362": {
    en: "Race Condition",
    ru: "состояние гонки",
    impact: "конкурентное выполнение может привести к обходу проверок или неконсистентному состоянию",
    remediation: "Установить исправления и проверить синхронизацию критичных операций."
  },
  "CWE-400": {
    en: "Uncontrolled Resource Consumption",
    ru: "неконтролируемое потребление ресурсов",
    impact: "возможен отказ в обслуживании из-за исчерпания CPU, памяти или соединений",
    remediation: "Обновить компонент и включить лимиты/квоты на дорогие операции."
  },
  "CWE-416": {
    en: "Use After Free",
    ru: "использование памяти после освобождения",
    impact: "возможны повреждение памяти, отказ в обслуживании или выполнение кода",
    remediation: "Установить исправленную версию и включить доступные exploit mitigations."
  },
  "CWE-434": {
    en: "Unrestricted File Upload",
    ru: "неограниченная загрузка файлов",
    impact: "атакующий может загрузить опасный файл и использовать его для компрометации сервиса",
    remediation: "Ограничить типы/размер файлов, хранить uploads вне webroot и установить патч."
  },
  "CWE-476": {
    en: "NULL Pointer Dereference",
    ru: "разыменование NULL-указателя",
    impact: "специальный ввод может привести к аварийному завершению процесса",
    remediation: "Обновить компонент и ограничить доступ к уязвимой функции до установки патча."
  },
  "CWE-502": {
    en: "Deserialization of Untrusted Data",
    ru: "десериализация недоверенных данных",
    impact: "возможны выполнение кода, обход логики или отказ в обслуживании при обработке объекта",
    remediation: "Запретить недоверенную десериализацию и установить исправления вендора."
  },
  "CWE-611": {
    en: "XXE",
    ru: "XXE-инъекция",
    impact: "XML-парсер может раскрыть локальные файлы или выполнить сетевые запросы",
    remediation: "Отключить внешние XML-сущности/DTD и установить исправления."
  },
  "CWE-787": {
    en: "Out-of-bounds Write",
    ru: "запись за пределами буфера",
    impact: "возможны повреждение памяти, отказ в обслуживании или выполнение кода",
    remediation: "Установить патч и снизить экспозицию уязвимого интерфейса."
  },
  "CWE-798": {
    en: "Hard-coded Credentials",
    ru: "зашитые учётные данные",
    impact: "атакующий может использовать известные ключи/пароли для доступа к системе",
    remediation: "Удалить/заменить статические секреты, ротировать ключи и обновить компонент."
  },
  "CWE-862": {
    en: "Missing Authorization",
    ru: "отсутствие проверки авторизации",
    impact: "пользователь может выполнить действие вне своих прав",
    remediation: "Установить патч и проверить контроль доступа на затронутых функциях."
  },
  "CWE-918": {
    en: "SSRF",
    ru: "подделка серверного запроса (SSRF)",
    impact: "сервер можно заставить обращаться к внутренним или внешним ресурсам",
    remediation: "Ограничить исходящие запросы allowlist-ом и установить исправления."
  }
};

function formatCweLabel(raw: string): string {
  const m = raw.match(/CWE-(\d+)/i);
  if (!m) return raw;
  const code = `CWE-${m[1]}`;
  const info = CWE_INFO[code];
  return info ? `${code} — ${info.ru}` : code;
}

function cweInfos(cwes: string[]): CweInfo[] {
  const out: CweInfo[] = [];
  for (const cwe of cwes) {
    const m = cwe.match(/CWE-(\d+)/i);
    const info = m ? CWE_INFO[`CWE-${m[1]}`] : undefined;
    if (info && !out.includes(info)) out.push(info);
  }
  return out;
}

function uniq(xs: Array<string | null | undefined>, limit = 8): string[] {
  const out: string[] = [];
  for (const x of xs) {
    const v = str(x).replace(/\s+/g, " ");
    if (!v) continue;
    if (out.some((y) => y.toLowerCase() === v.toLowerCase())) continue;
    out.push(v);
    if (out.length >= limit) break;
  }
  return out;
}

/** Класс уязвимости из NVD (CWE + краткое имя). */
export function extractNvdVulnerabilityClass(raw: unknown): string | null {
  const o = asObj(raw);
  if (!o) return null;
  const labels = extractCweLabels(o).map(formatCweLabel);
  return labels.length > 0 ? labels.join(", ") : null;
}

const CVSS_AV_RU: Record<string, string> = {
  NETWORK: "сетевая",
  ADJACENT: "смежная сеть",
  LOCAL: "локальная",
  PHYSICAL: "физический доступ"
};

const CVSS_IMPACT_RU: Record<string, string> = {
  HIGH: "высокое",
  LOW: "низкое",
  NONE: "нет"
};

type CvssHints = {
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  confidentialityImpact?: string;
  integrityImpact?: string;
  availabilityImpact?: string;
};

function firstCvssHints(raw: JsonObj): CvssHints {
  const metrics = asObj(raw.metrics);
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const arr = metrics?.[key];
    if (!Array.isArray(arr) || !arr[0]) continue;
    const cvssData = asObj(asObj(arr[0])?.cvssData);
    if (!cvssData) continue;
    return {
      attackVector: str(cvssData.attackVector).toUpperCase(),
      attackComplexity: str(cvssData.attackComplexity).toUpperCase(),
      privilegesRequired: str(cvssData.privilegesRequired).toUpperCase(),
      userInteraction: str(cvssData.userInteraction).toUpperCase(),
      confidentialityImpact: str(cvssData.confidentialityImpact).toUpperCase(),
      integrityImpact: str(cvssData.integrityImpact).toUpperCase(),
      availabilityImpact: str(cvssData.availabilityImpact).toUpperCase()
    };
  }
  return {};
}

/** Подсказка по эксплуатации из CVSS NVD, если ИИ не дал деталей. */
export function extractNvdExploitationHint(raw: unknown, exploitKnown = false): string | null {
  if (exploitKnown) return "В KEV / известна активная эксплуатация";
  const o = asObj(raw);
  if (!o) return null;
  const metrics = asObj(o.metrics);
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const arr = metrics?.[key];
    if (!Array.isArray(arr) || !arr[0]) continue;
    const cvssData = asObj(asObj(arr[0])?.cvssData);
    const av = str(cvssData?.attackVector).toUpperCase();
    const ac = str(cvssData?.attackComplexity).toUpperCase();
    const pr = str(cvssData?.privilegesRequired).toUpperCase();
    const parts: string[] = [];
    if (av) parts.push(`вектор ${CVSS_AV_RU[av] ?? av.toLowerCase()}`);
    if (ac === "LOW") parts.push("низкая сложность атаки");
    if (pr === "NONE") parts.push("без привилегий");
    if (parts.length > 0) return `По CVSS: ${parts.join(", ")}`;
  }
  return null;
}

function productLabelFromCpe(criteria: string): string | null {
  const parts = criteria.split(":");
  if (parts.length < 5) return null;
  const vendorRaw = parts[3] ?? "";
  const productRaw = parts[4] ?? "";
  const vendor = vendorRaw === "*" ? "" : vendorRaw.replace(/_/g, " ");
  const product = productRaw === "*" ? "" : productRaw.replace(/_/g, " ");
  if (vendor === "linux" && product === "linux kernel") return "Linux kernel";
  if (product && vendor && !product.toLowerCase().startsWith(vendor.toLowerCase())) return `${vendor} ${product}`;
  return product || vendor || null;
}

function extractProductHints(raw: JsonObj): string[] {
  const out: string[] = [];
  const configs = raw.configurations;
  const nodes: unknown[] = [];
  if (Array.isArray(configs)) {
    for (const cfg of configs) {
      const cfgObj = asObj(cfg);
      if (Array.isArray(cfgObj?.nodes)) nodes.push(...cfgObj.nodes);
    }
  } else if (Array.isArray(asObj(configs)?.nodes)) {
    nodes.push(...(asObj(configs)?.nodes as unknown[]));
  }

  for (const node of nodes) {
    const matches = asObj(node)?.cpeMatch;
    if (!Array.isArray(matches)) continue;
    for (const m of matches) {
      const match = asObj(m);
      if (!match || match.vulnerable === false) continue;
      const label = productLabelFromCpe(str(match.criteria));
      if (label && !out.some((x) => x.toLowerCase() === label.toLowerCase())) out.push(label);
      if (out.length >= 3) return out;
    }
  }
  return out;
}

function likelyExploitKnown(raw: JsonObj): boolean {
  const boolKeys = ["cisa_kev", "cisaKev", "kev", "known_exploited", "has_public_exploit", "hasExploit"];
  if (boolKeys.some((k) => raw[k] === true)) return true;
  const refs = raw.references;
  if (!Array.isArray(refs)) return false;
  return refs.some((item) => {
    const ref = asObj(item);
    const tags = Array.isArray(ref?.tags) ? ref.tags.map((x) => String(x).toLowerCase()) : [];
    const url = str(ref?.url);
    return tags.some((t) => t.includes("exploit")) || /exploit-db|metasploit|packetstormsecurity/i.test(url);
  });
}

function impactFromDescription(desc: string): string | null {
  const lower = desc.toLowerCase();
  if (/remote code execution|execute arbitrary code|arbitrary code execution|code execution/.test(lower)) {
    return "может привести к удалённому выполнению произвольного кода";
  }
  if (/privilege escalation|escalat(e|ion) of privilege|gain privileges/.test(lower)) {
    return "может привести к повышению привилегий";
  }
  if (/denial of service|crash|panic|resource exhaustion/.test(lower)) {
    return "может привести к отказу в обслуживании";
  }
  if (/information disclosure|information leak|exposure of sensitive|read arbitrary/.test(lower)) {
    return "может привести к раскрытию информации";
  }
  if (/authentication bypass|bypass authentication/.test(lower)) {
    return "может привести к обходу аутентификации";
  }
  if (/authorization bypass|bypass authorization|access control/.test(lower)) {
    return "может привести к обходу авторизации";
  }
  return null;
}

function cvssImpactSummary(hints: CvssHints): string | null {
  const parts = [
    hints.confidentialityImpact ? `конфиденциальность: ${CVSS_IMPACT_RU[hints.confidentialityImpact] ?? hints.confidentialityImpact.toLowerCase()}` : null,
    hints.integrityImpact ? `целостность: ${CVSS_IMPACT_RU[hints.integrityImpact] ?? hints.integrityImpact.toLowerCase()}` : null,
    hints.availabilityImpact ? `доступность: ${CVSS_IMPACT_RU[hints.availabilityImpact] ?? hints.availabilityImpact.toLowerCase()}` : null
  ].filter(Boolean);
  return parts.length ? `По CVSS влияние: ${parts.join(", ")}.` : null;
}

function buildRuNvdSummary(opts: {
  cveId: string;
  product: string | null;
  vulnClass: string | null;
  cweImpacts: string[];
  descImpact: string | null;
  exploitKnown: boolean;
  cvss: CvssHints;
}): string {
  const subject = opts.product ? `затрагивает ${opts.product}` : "затрагивает уязвимый компонент";
  const parts = [`${opts.cveId} ${subject}.`];
  if (opts.vulnClass) parts.push(`Класс: ${opts.vulnClass}.`);
  const impact = opts.descImpact ?? opts.cweImpacts[0] ?? null;
  if (impact) parts.push(`Суть риска: ${impact}.`);
  const cvssBits = [
    opts.cvss.attackVector ? `вектор ${CVSS_AV_RU[opts.cvss.attackVector] ?? opts.cvss.attackVector.toLowerCase()}` : null,
    opts.cvss.attackComplexity === "LOW" ? "низкая сложность атаки" : null,
    opts.cvss.privilegesRequired === "NONE" ? "без привилегий" : null,
    opts.cvss.userInteraction === "NONE" ? "без участия пользователя" : null
  ].filter(Boolean);
  if (cvssBits.length) parts.push(`Условия эксплуатации: ${cvssBits.join(", ")}.`);
  if (opts.exploitKnown) parts.push("Есть признаки KEV/публичной эксплуатации, приоритизируйте проверку и патчинг.");
  return parts.join(" ");
}

function buildBaselineRemediation(opts: {
  product: string | null;
  cvssNetwork: boolean;
  exploitKnown: boolean;
  cweRemediations: string[];
}): string[] {
  const product = opts.product ?? "затронутого компонента";
  return uniq(
    [
      `Сверить установленные версии ${product} с диапазонами NVD/CPE и advisory вендора.`,
      "Установить исправленную версию или официальный патч вендора при наличии.",
      opts.cvssNetwork ? "До обновления ограничить сетевой доступ к уязвимому интерфейсу (ACL/VPN/WAF)." : null,
      opts.exploitKnown ? "Из-за признаков эксплуатации проверить логи и IoC по публичным источникам." : null,
      ...opts.cweRemediations
    ],
    6
  );
}

function shortRuSummary(text: string, max = 420): string {
  const t = text.replace(/\s+/g, " ").trim();
  if (!t) return "";
  if (t.length <= max) return t;
  const cut = t.slice(0, max);
  const last = Math.max(cut.lastIndexOf(". "), cut.lastIndexOf(" "));
  return `${(last > 80 ? cut.slice(0, last) : cut).trim()}…`;
}

function defaultAttackFlow(cvssNetwork: boolean): string[] {
  return cvssNetwork
    ? [
        "Злоумышленник находит сетевую точку входа, где обрабатываются входные данные.",
        "Передаёт специально сформированный запрос или данные в уязвимый компонент.",
        "Уязвимая логика некорректно обрабатывает ввод и достигает опасного кода.",
        "Возникает заявленное воздействие (компрометация, утечка, отказ в обслуживании)."
      ]
    : [
        "Злоумышленник получает возможность влиять на входные данные уязвимого компонента.",
        "Эксплуатирует дефект проверок или обработки данных.",
        "Достигает заявленного воздействия в пределах модели угроз CVE."
      ];
}

/** Схема атаки по умолчанию для карточек/TG без ИИ. */
export function defaultAttackFlowSteps(raw?: unknown): string[] {
  const o = asObj(raw) ?? {};
  return defaultAttackFlow(cvssAttackVectorNetwork(o));
}

export type BaselineAttackGraph = {
  nodes: { id: string; label: string; type: string }[];
  edges: { from: string; to: string; label?: string }[];
};

/** Пустой stub `{nodes:[],edges:[]}` или не-объект — не годится для UI. */
export function isUsableAttackGraph(g: unknown): g is BaselineAttackGraph {
  const o = asObj(g);
  if (!o) return false;
  const nodes = o.nodes;
  const edges = o.edges;
  return (Array.isArray(nodes) && nodes.length > 0) || (Array.isArray(edges) && edges.length > 0);
}

/**
 * Детерминированный граф атаки из CVSS/CWE/продукта и attackFlow —
 * чтобы карточки сразу показывали схему без LLM.
 */
export function buildBaselineAttackGraph(opts: {
  entityId: string;
  attackFlow?: string[];
  summary?: string;
  product?: string | null;
  vulnClass?: string | null;
  cvssNetwork?: boolean;
}): BaselineAttackGraph {
  const flow = (opts.attackFlow ?? []).map((s) => String(s).trim()).filter(Boolean);
  const text = `${opts.summary ?? ""}\n${opts.vulnClass ?? ""}\n${flow.join("\n")}`.toLowerCase();
  const has = (...needles: string[]) => needles.some((n) => text.includes(n));

  const techniqueLabel = has("десериал", "deserialize", "serialization")
    ? "Техника: десериализация"
    : has("инъекц", "injection", "sql", "command injection")
      ? "Техника: инъекция"
      : has("ssrf")
        ? "Техника: SSRF"
        : has("xss", "cross-site")
          ? "Техника: XSS"
          : has("path traversal", "directory traversal", "обход пут", "../")
            ? "Техника: Path Traversal"
            : has("переполн", "overflow", "buffer")
              ? "Техника: переполнение буфера"
              : opts.vulnClass
                ? `Техника: ${opts.vulnClass}`
                : null;

  const impactLabel =
    has("rce", "выполн", "код", "remote code")
      ? "Выполнение кода"
      : has("утеч", "конфиденц", "disclosure", "information")
        ? "Утечка данных"
        : has("dos", "отказ", "доступност", "denial")
          ? "Отказ в обслуживании"
          : has("privilege", "эскалац", "повыш")
            ? "Повышение привилегий"
            : "Компрометация";

  const vectorLabel = opts.cvssNetwork
    ? has("http", "api", "заголов", "header", "web")
      ? "Сетевой запрос (HTTP/API)"
      : "Сетевой вектор атаки"
    : has("file", "файл", "document", "документ")
      ? "Локальный файл/документ"
      : "Локальный/смежный вектор";

  const serviceLabel = opts.product
    ? `Уязвимый компонент: ${opts.product}`
    : `Уязвимый компонент (${opts.entityId})`;

  const nodes: BaselineAttackGraph["nodes"] = [
    { id: "attacker", label: "Злоумышленник", type: "attacker" },
    { id: "vector", label: vectorLabel, type: "vector" },
    { id: "service", label: serviceLabel, type: "service" },
    { id: "asset", label: "Целевая система/сервис", type: "asset" },
    { id: "impact", label: `Воздействие: ${impactLabel}`, type: "impact" }
  ];
  const edges: BaselineAttackGraph["edges"] = [
    { from: "attacker", to: "vector", label: "использует" },
    { from: "vector", to: "service", label: "доставляет payload" },
    { from: "service", to: "asset", label: "затрагивает" },
    { from: "asset", to: "impact", label: "приводит к" }
  ];

  if (techniqueLabel) {
    nodes.push({ id: "technique", label: techniqueLabel, type: "vector" });
    edges.push({ from: "vector", to: "technique", label: "эксплуатирует" });
    edges.push({ from: "technique", to: "service", label: "триггерит" });
  }

  return { nodes, edges };
}

function cvssAttackVectorNetwork(raw: JsonObj): boolean {
  const metrics = asObj(raw.metrics);
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const arr = metrics?.[key];
    if (!Array.isArray(arr) || !arr[0]) continue;
    const cvssData = asObj(asObj(arr[0])?.cvssData);
    const av = str(cvssData?.attackVector);
    if (av.toUpperCase() === "NETWORK") return true;
  }
  return false;
}

/** NETWORK AV в CVSS (или false, если raw нет/не разобран). */
export function isCvssAttackVectorNetwork(raw?: unknown): boolean {
  return cvssAttackVectorNetwork(asObj(raw) ?? {});
}

/**
 * Минимальная «карточка» из NVD без вызова LLM — для всех CVE с raw в БД.
 */
export function buildBaselineEnrichmentFromNvd(cveId: string, raw: unknown): JsonObj {
  const o = asObj(raw) ?? {};
  const desc = firstDescription(o);
  const cwes = extractCweLabels(o);
  const vulnClass = cwes.length > 0 ? cwes.map(formatCweLabel).join(", ") : null;
  const productHints = extractProductHints(o);
  const productHint = productHints[0] ?? null;
  const cvss = firstCvssHints(o);
  const cweDetails = cweInfos(cwes);
  const exploitKnown = likelyExploitKnown(o);
  const cvssNetwork = cvssAttackVectorNetwork(o);

  const title = productHint
    ? `${cveId}: уязвимость в ${productHint}`
    : vulnClass
      ? `${cveId}: ${vulnClass}`
      : `Уязвимость ${cveId}`;

  const summary = buildRuNvdSummary({
    cveId,
    product: productHint,
    vulnClass,
    cweImpacts: cweDetails.map((x) => x.impact),
    descImpact: impactFromDescription(desc),
    exploitKnown,
    cvss
  });

  const cvssImpact = cvssImpactSummary(cvss);
  const descLooksRu = /[А-Яа-яЁё]/.test(desc) && (desc.match(/[А-Яа-яЁё]/g)?.length ?? 0) >= 8;
  const descriptionParts = [
    summary,
    cvssImpact,
    desc
      ? descLooksRu
        ? `Описание источника: ${shortRuSummary(desc, 1600)}`
        : `Описание NVD: ${shortRuSummary(desc, 1600)}`
      : null
  ].filter(Boolean);
  const description = descriptionParts.join("\n\n") || `Запись ${cveId} в NVD.`;
  const remediation = buildBaselineRemediation({
    product: productHint,
    cvssNetwork,
    exploitKnown,
    cweRemediations: cweDetails.map((x) => x.remediation)
  });
  const attackFlow = defaultAttackFlowSteps(o);

  const base: JsonObj = {
    title,
    summary,
    description: description.length > 2800 ? `${description.slice(0, 2800)}…` : description,
    vulnerabilityClass: vulnClass,
    attackFlow,
    exploitation: {
      publicExploit: exploitKnown ? "yes" : "unknown",
      exploitNotes: extractNvdExploitationHint(o, exploitKnown)
    },
    consequences: uniq(
      [
        vulnClass ? `Класс уязвимости: ${vulnClass}` : null,
        ...cweDetails.map((x) => x.impact),
        impactFromDescription(desc),
        cvssImpact
      ],
      5
    ),
    remediation,
    applicability: { status: "unknown", notes: "Требуется сверка версий ПО в вашем окружении." },
    nextSteps: uniq(
      [
        "Сопоставить CPE/версии из NVD с инвентарём активов.",
        productHints.length > 1 ? `Проверить также похожие продукты из CPE: ${productHints.slice(1).join(", ")}.` : null,
        exploitKnown ? "Поднять приоритет triage: есть признаки KEV/публичного эксплойта." : null,
        cvssNetwork ? "Проверить внешнюю экспозицию сервиса и временно ограничить доступ." : null
      ],
      6
    ),
    questions: [
      "Какие версии затронутого ПО установлены на критичных активах?",
      "Есть ли экспозиция уязвимого компонента извне (интернет/VPN)?"
    ],
    sources: [],
    graph: buildBaselineAttackGraph({
      entityId: cveId,
      attackFlow,
      summary,
      product: productHint,
      vulnClass,
      cvssNetwork
    }),
    uncertainties: [],
    _display_source: "nvd_baseline"
  };

  return augmentEnrichmentWithNvdFixes(base, o);
}
