import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import {
  DIGEST_NARRATIVE_SKIPPED,
  buildDigestNarrativePrompt,
  buildMonthlyDigestPrompt,
  capDigestPrompt,
  composeDigestStory,
  digestFactsText,
  filterDigestNarrative,
  digestLlmConfigFromStored,
  getVulnContextLlmConfigFromEnv,
  isDigestNarrativeConfigured,
  resolveOpenAiCompatibleChatUrl,
  runDigestNarrative,
  shouldEnrichViaQueue,
  parseOpenWebDigest
} from "../dist/index.js";

const envBackup = {
  LLM_ENDPOINT: process.env.LLM_ENDPOINT,
  LLM_MODEL: process.env.LLM_MODEL,
  LLM_API_KEY: process.env.LLM_API_KEY,
  XAI_API_KEY: process.env.XAI_API_KEY,
  DASHSCOPE_API_KEY: process.env.DASHSCOPE_API_KEY
};

afterEach(() => {
  for (const [key, value] of Object.entries(envBackup)) {
    if (value == null) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("DeepSeek chat URL", () => {
  it("turns the DeepSeek base into chat completions and keeps full OpenAI URLs", () => {
    assert.equal(
      resolveOpenAiCompatibleChatUrl("https://api.deepseek.com"),
      "https://api.deepseek.com/chat/completions"
    );
    assert.equal(
      resolveOpenAiCompatibleChatUrl("https://api.deepseek.com/v1"),
      "https://api.deepseek.com/v1/chat/completions"
    );
    assert.equal(
      resolveOpenAiCompatibleChatUrl("https://api.openai.com/v1/chat/completions"),
      "https://api.openai.com/v1/chat/completions"
    );
    assert.equal(
      resolveOpenAiCompatibleChatUrl("http://127.0.0.1:11434/v1/chat/completions"),
      "http://127.0.0.1:11434/v1/chat/completions"
    );
  });

  it("defaults the model to deepseek-chat when the endpoint is DeepSeek", () => {
    process.env.LLM_ENDPOINT = "https://api.deepseek.com";
    delete process.env.LLM_MODEL;
    delete process.env.LLM_API_KEY;
    delete process.env.XAI_API_KEY;
    delete process.env.DASHSCOPE_API_KEY;
    const config = getVulnContextLlmConfigFromEnv();
    assert.equal(config.endpoint, "https://api.deepseek.com");
    assert.equal(config.model, "deepseek-chat");
    assert.equal(config.apiKey, "");
  });
});

describe("digest narrative filter", () => {
  const facts = digestFactsText({
    title: "Отчёт",
    windowLabel: "Последние 30 дней",
    issuedAt: "2026-10-14T12:00:00.000Z",
    coverage: "Сводка каталога.",
    sections: [
      {
        title: "Сводка каталога",
        status: "ready",
        note: "",
        metrics: [{ label: "Всего CVE", value: "12 345" }],
        bars: [],
        tables: []
      }
    ],
    cveNotes: [{ cveId: "CVE-2024-1000", description: "Короткое описание в Apache HTTP Server." }]
  });

  it("drops sentences with numbers or CVE ids that are not in the facts", () => {
    const text = filterDigestNarrative(
      "В каталоге 12345 CVE, включая CVE-2024-1000. Появилось 999 новых. Продукт Apache HTTP Server упомянут в описании.",
      facts
    );
    assert.match(text, /12345/);
    assert.match(text, /CVE-2024-1000/);
    assert.equal(text.includes("999"), false);
    assert.match(text, /Apache HTTP Server/);
  });

  it("drops an invented CVE even when the year is already present", () => {
    const text = filterDigestNarrative("Смотрите CVE-2024-9999 в том же окне.", facts);
    assert.equal(text, "");
  });

  it("caps the prompt and does not call the model without a key", async () => {
    const long = "x".repeat(9000);
    assert.ok(capDigestPrompt(long).length <= 8000);
    assert.ok(buildDigestNarrativePrompt(facts).includes("FACTS:"));
    assert.equal(buildDigestNarrativePrompt(facts).includes("```"), false);
    const outcome = await runDigestNarrative({
      facts: {
        title: "Отчёт",
        windowLabel: "Последние 30 дней",
        issuedAt: "2026-10-14T12:00:00.000Z",
        coverage: "",
        sections: [],
        cveNotes: []
      },
      llm: {
        endpoint: "https://api.deepseek.com",
        apiKey: "",
        model: "deepseek-chat",
        promptVersion: "digest-v1"
      }
    });
    assert.equal(outcome.status, "skipped");
    assert.equal(outcome.text, DIGEST_NARRATIVE_SKIPPED);
    assert.equal(outcome.lead, DIGEST_NARRATIVE_SKIPPED);
  });

  it("keeps a stored digest key out of the env LLM profile", () => {
    process.env.LLM_API_KEY = "env-profile-key";
    process.env.LLM_ENDPOINT = "https://api.openai.com/v1/chat/completions";
    const fromEnv = getVulnContextLlmConfigFromEnv();
    const digest = digestLlmConfigFromStored(undefined);
    assert.equal(fromEnv.apiKey, "env-profile-key");
    assert.equal(digest.apiKey, "");
    assert.equal(digest.endpoint, "https://api.deepseek.com");
    assert.equal(digest.model, "deepseek-chat");
    const stored = digestLlmConfigFromStored({
      endpoint: "https://api.deepseek.com",
      model: "deepseek-chat",
      apiKey: "digest-only"
    });
    assert.equal(stored.apiKey, "digest-only");
    assert.notEqual(stored.apiKey, fromEnv.apiKey);
  });

  it("treats a digest key as ready without turning on catalog enrichment", () => {
    assert.equal(isDigestNarrativeConfigured({ endpoint: "https://api.deepseek.com", apiKey: "" }), false);
    assert.equal(isDigestNarrativeConfigured({ endpoint: "https://api.deepseek.com", apiKey: "present" }), true);
    const prev = process.env.AI_ENRICH_VIA_QUEUE;
    delete process.env.AI_ENRICH_VIA_QUEUE;
    try {
      assert.equal(shouldEnrichViaQueue("baseline"), false);
      assert.equal(shouldEnrichViaQueue("translate"), false);
      assert.equal(shouldEnrichViaQueue("llm"), true);
    } finally {
      if (prev == null) delete process.env.AI_ENRICH_VIA_QUEUE;
      else process.env.AI_ENRICH_VIA_QUEUE = prev;
    }
  });

  it("asks the monthly prompt to stay inside catalog facts and does not call DeepSeek without a digest key", async () => {
    const prompt = buildMonthlyDigestPrompt("Опубликовано: 3");
    assert.match(prompt, /Запрещено выдумывать CVE/);
    assert.match(prompt, /календарный месяц/);
    assert.equal(prompt.includes("```"), false);
    const outcome = await runDigestNarrative({
      facts: {
        title: "Дайджест",
        windowLabel: "1–30 сентября 2026",
        issuedAt: "14 октября 2026",
        coverage: "Каталог.",
        sections: [],
        cveNotes: []
      },
      llm: {
        endpoint: "https://api.deepseek.com",
        apiKey: "",
        model: "deepseek-chat",
        promptVersion: "digest-v1"
      },
      kind: "month"
    });
    assert.equal(outcome.status, "skipped");
    assert.equal(outcome.text, DIGEST_NARRATIVE_SKIPPED);
  });

  it("keeps a real lead and drops a case sentence with a number outside the facts", () => {
    const story = composeDigestStory(
      [
        "LEAD: В каталоге 12345 CVE, включая CVE-2024-1000.",
        "SUMMARY: Описание относится к Apache HTTP Server.",
        "CASES: CVE-2024-1000 упомянут в описании. CVE-2024-9999 добавлен отдельно.",
        "CLOSE: Читать выпуск по фактам каталога."
      ].join("\n"),
      facts
    );
    assert.match(story.lead, /12345/);
    assert.match(story.lead, /CVE-2024-1000/);
    assert.equal(story.cases.includes("9999"), false);
    assert.match(story.cases, /CVE-2024-1000/);
    assert.match(story.close, /фактам каталога/);
  });
});

describe("open web digest brief", () => {
  const sources = [
    "Новых CISA KEV за этот месяц: 43. За предыдущий месяц: 31.",
    "Публикаций NVD за этот месяц, totalResults: 14959.",
    "CVE-2026-85706 GitLab",
    "CVE-2026-88771 Citrix"
  ].join("\n");

  it("keeps sourced figures and drops invented CVE, KPI and host advice", () => {
    const raw = JSON.stringify({
      focus: "Фокус на записях CISA KEV и публикациях NVD.",
      lead: "За месяц открытые выгрузки дали 43 новые записи CISA KEV и 14959 публикаций NVD. В них есть CVE-2026-85706 для GitLab и CVE-2026-88771 для Citrix. Отчёт читается как брифинг по продуктам, а не как сводка внутреннего каталога.",
      audience: "Текст для команды vulnerability management: какие продукты месяца закрывать патчем раньше остальных.",
      kpis: [
        { value: "14959", label: "публикаций NVD" },
        { value: "43", label: "новых CISA KEV" },
        { value: "99999", label: "выдуманный сигнал" }
      ],
      sections: [
        { title: "Executive Summary", headline: "KEV задал приоритет месяца", paragraphs: ["В выгрузке KEV 43 записи, включая CVE-2026-85706."], bullets: ["GitLab и Citrix есть в KEV."] },
        { title: "Месяц в цифрах", paragraphs: ["NVD totalResults равен 14959. Для KEV в фактах есть 43 против 31."], bullets: [] },
        { title: "Динамика CVE", paragraphs: ["Сравнение опирается на 14959 против прошлого месяца только если оно есть в сырье."], bullets: [] },
        { title: "Критичность уязвимостей", paragraphs: ["Формальная критичность не равна фактическому риску."], bullets: [] },
        { title: "Реальная эксплуатация", paragraphs: ["KEV отмечает уже идущую эксплуатацию."], bullets: [] },
        { title: "Топ уязвимостей", paragraphs: ["В таблицу попали только CVE из выгрузки."], bullets: [], table: { columns: ["CVE", "Продукт", "Сигнал", "Риск"], rows: [["CVE-2026-85706", "GitLab", "KEV", "чтение файлов"], ["CVE-2099-00001", "Example", "KEV", "выдумка"]] } },
        { title: "План на 72 часа", paragraphs: ["Сверьте версии продуктов из KEV и поставьте задачу на патч."], bullets: ["Заведите Jira и обойдите хосты."] },
        { title: "Методология и источники", paragraphs: ["Источники: CISA KEV и NVD."], bullets: [] }
      ],
      closing: "Месяц задали 43 записи KEV, а не длина списка по одному CVSS."
    });
    const doc = parseOpenWebDigest(raw, sources);
    assert.ok(doc);
    assert.deepEqual(doc.kpis.map((item) => item.value), ["14959", "43"]);
    const table = doc.sections.find((section) => section.title.startsWith("Топ"))?.table;
    assert.equal(table?.rows.length, 1);
    assert.equal(table?.rows[0]?.[0], "CVE-2026-85706");
    const actions = doc.sections.find((section) => section.title.includes("72"));
    assert.equal(actions?.bullets.length, 0);
    assert.match(actions?.paragraphs[0] ?? "", /патч/);
  });
});
