import { Injectable, OnModuleInit } from "@nestjs/common";
import { DbService } from "./db.service.js";

@Injectable()
export class SchemaService implements OnModuleInit {
  constructor(private readonly db: DbService) {}

  async onModuleInit() {
    // Keep API compatible with existing DB volumes.
    await this.db.query(
      `ALTER TABLE cve
       ADD COLUMN IF NOT EXISTS cvss_base DOUBLE PRECISION CHECK (cvss_base >= 0 AND cvss_base <= 10)`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS cve_vendor_product (
        cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
        vendor TEXT NOT NULL,
        product TEXT,
        vendor_key TEXT NOT NULL,
        product_key TEXT,
        product_key_norm TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL,
        cve_updated_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (cve_id, vendor_key, product_key_norm)
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_vendor_product_vendor_idx ON cve_vendor_product (vendor_key)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_vendor_product_vendor_product_idx ON cve_vendor_product (vendor_key, product_key_norm)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_vendor_product_cve_idx ON cve_vendor_product (cve_id)`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS auth_user (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        totp_secret TEXT,
        totp_pending_secret TEXT,
        totp_enabled BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS auth_user_email_lower_idx ON auth_user (lower(email))`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS refresh_token (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES auth_user(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        revoked_at TIMESTAMPTZ
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS refresh_token_user_idx ON refresh_token (user_id)`
    );
    await this.db.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS refresh_token_hash_active_idx
         ON refresh_token (token_hash)
        WHERE revoked_at IS NULL`
    );
    /** Ранее refresh_token ссылался на app_user → переименовали в auth_user; перепривязываем FK. */
    await this.db.query(
      `ALTER TABLE refresh_token DROP CONSTRAINT IF EXISTS refresh_token_user_id_fkey`
    );
    await this.db.query(`DELETE FROM refresh_token`);
    try {
      await this.db.query(
        `ALTER TABLE refresh_token
          ADD CONSTRAINT refresh_token_user_id_fkey
          FOREIGN KEY (user_id) REFERENCES auth_user(id) ON DELETE CASCADE`
      );
    } catch (e: unknown) {
      const err = e as { code?: string };
      /** Параллельный старт или FK уже создан inline в CREATE TABLE — constraint уже есть. */
      if (err?.code !== "42710") throw e;
    }
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS epss_score (
        cve_id TEXT PRIMARY KEY,
        score DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 1),
        percentile DOUBLE PRECISION CHECK (percentile >= 0 AND percentile <= 1),
        scored_at DATE,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS kev (
        cve_id TEXT PRIMARY KEY,
        vendor_project TEXT,
        product TEXT,
        vulnerability_name TEXT,
        date_added DATE,
        due_date DATE,
        required_action TEXT,
        ransomware_use TEXT,
        notes TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS vendor_advisory (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        dedupe_key TEXT NOT NULL UNIQUE,
        feed_url TEXT NOT NULL,
        vendor_slug TEXT NOT NULL,
        title TEXT NOT NULL,
        link TEXT NOT NULL,
        summary TEXT,
        published_at TIMESTAMPTZ,
        cve_ids TEXT[] NOT NULL DEFAULT '{}',
        raw_item JSONB,
        fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS vendor_advisory_published_idx ON vendor_advisory (published_at DESC NULLS LAST)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS vendor_advisory_vendor_idx ON vendor_advisory (vendor_slug)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS vendor_advisory_cve_ids_gin_idx ON vendor_advisory USING gin (cve_ids)`
    );

    await this.seedVendorAdvisoryDemoRows();

    // --- Vulnerability task tracker (CVE tasks) ---
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS vuln_task (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'new'
          CHECK (status IN ('new','in_progress','needs_info','fixing','mitigated','closed','not_applicable','risk_accepted')),
        priority_local TEXT NOT NULL DEFAULT 'medium'
          CHECK (priority_local IN ('low','medium','high','critical')),
        owner TEXT,
        due_date TIMESTAMPTZ,
        review_date TIMESTAMPTZ,
        vendor_key TEXT NOT NULL,
        vendor_display TEXT NOT NULL,
        product_key_norm TEXT NOT NULL DEFAULT '',
        product_display TEXT NOT NULL DEFAULT '',
        notes_md TEXT NOT NULL DEFAULT '',
        decision TEXT,
        decision_notes TEXT,
        evidence TEXT,
        closed_at TIMESTAMPTZ,
        -- cached scoring (recomputed on write)
        score_raw INT NOT NULL DEFAULT 0 CHECK (score_raw >= 0 AND score_raw <= 100),
        score_final INT NOT NULL DEFAULT 0 CHECK (score_final >= 0 AND score_final <= 100),
        score_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
        stats JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS vuln_task_updated_idx ON vuln_task (updated_at DESC)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS vuln_task_status_idx ON vuln_task (status)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS vuln_task_vendor_product_idx ON vuln_task (vendor_key, product_key_norm)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS vuln_task_score_final_idx ON vuln_task (score_final DESC, updated_at DESC)`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS vuln_task_cve (
        task_id UUID NOT NULL REFERENCES vuln_task(id) ON DELETE CASCADE,
        cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
        added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        note TEXT,
        PRIMARY KEY (task_id, cve_id)
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS vuln_task_cve_cve_idx ON vuln_task_cve (cve_id)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS vuln_task_cve_task_idx ON vuln_task_cve (task_id)`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS vuln_task_event (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        task_id UUID NOT NULL REFERENCES vuln_task(id) ON DELETE CASCADE,
        ts TIMESTAMPTZ NOT NULL DEFAULT now(),
        actor TEXT,
        action TEXT NOT NULL,
        before JSONB,
        after JSONB,
        meta JSONB NOT NULL DEFAULT '{}'::jsonb
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS vuln_task_event_task_ts_idx ON vuln_task_event (task_id, ts DESC)`);

    // --- ASV / External attack surface management (assets + scan runs + findings) ---
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS asv_asset (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        asset_type TEXT NOT NULL CHECK (asset_type IN ('domain','ip','cidr','url')),
        key_norm TEXT NOT NULL,
        display_name TEXT NOT NULL,
        scope_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (asset_type, key_norm)
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_asset_type_idx ON asv_asset (asset_type)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_asset_updated_idx ON asv_asset (updated_at DESC)`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS asv_scan_profile (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL UNIQUE,
        mode TEXT NOT NULL DEFAULT 'safe' CHECK (mode IN ('safe','standard')),
        config JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );

    // Default profiles (idempotent).
    await this.db.query(
      `INSERT INTO asv_scan_profile (name, mode, config)
       VALUES
        (
          'safe',
          'safe',
          '{
            "ports": [80,443,8080,8443,22,3389,445],
            "httpPaths": ["/"],
            "nuclei": { "enabled": true, "tags": ["misconfiguration","misconfig","exposed-panels","panel","technologies","tech","exposure","default-login","osint","takeovers"], "excludeTags": ["intrusive","dos","fuzz"], "severity": ["critical","high","medium","low","info"], "rateLimitPerMin": 240, "maxMs": 240000 },
            "tcpTimeoutMs": 800,
            "httpTimeoutMs": 2500,
            "maxPortConcurrency": 24,
            "maxHttpConcurrency": 8
          }'::jsonb
        ),
        (
          'standard',
          'standard',
          '{
            "ports": [21,22,23,25,53,80,81,88,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,2049,2375,27017,3000,3306,3389,4000,5000,5432,5601,5900,6379,8000,8080,8443,9000,9200,9300,11211],
            "httpPaths": ["/","/robots.txt","/.well-known/security.txt","/sitemap.xml","/favicon.ico"],
            "nuclei": { "enabled": true, "tags": ["cve","misconfiguration","misconfig","exposed-panels","panel","technologies","tech","exposure","takeovers","default-login","osint","vuln","kubernetes","k8s","cloud","devops","config","authentication","microsoft","azure","aws","gcp","firebase","jwt","oauth","graphql","swagger","api"], "excludeTags": ["intrusive","dos","fuzz"], "severity": ["critical","high","medium","low","info"], "rateLimitPerMin": 600, "maxMs": 900000 },
            "tcpTimeoutMs": 800,
            "httpTimeoutMs": 2200,
            "maxPortConcurrency": 64,
            "maxHttpConcurrency": 16
          }'::jsonb
        ),
        (
          'monster',
          'standard',
          '{
            "ports": [21,22,23,25,53,80,81,88,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,2049,2375,27017,3000,3306,3389,4000,5000,5432,5601,5900,6379,8000,8080,8443,9000,9200,9300,11211],
            "httpPaths": ["/","/robots.txt","/.well-known/security.txt","/sitemap.xml","/favicon.ico","/.git/config","/.env","/actuator/health","/swagger-ui/","/api-docs","/graphql"],
            "nuclei": { "enabled": true, "tags": ["cve","vuln","misconfiguration","misconfig","exposed-panels","panel","default-login","takeovers","tech","exposure","kubernetes","cloud","devops","api"], "excludeTags": ["intrusive","dos","fuzz"], "severity": ["critical","high","medium","low","info"], "rateLimitPerMin": 900, "maxMs": 1800000 },
            "tcpTimeoutMs": 900,
            "httpTimeoutMs": 3500,
            "maxPortConcurrency": 96,
            "maxHttpConcurrency": 24
          }'::jsonb
        )
       ON CONFLICT (name) DO UPDATE
         SET mode = EXCLUDED.mode,
             config = EXCLUDED.config,
             updated_at = now()`
    );

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS asv_scan_run (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        asset_id UUID NOT NULL REFERENCES asv_asset(id) ON DELETE CASCADE,
        profile_id UUID REFERENCES asv_scan_profile(id) ON DELETE SET NULL,
        scan_mode TEXT NOT NULL DEFAULT 'safe' CHECK (scan_mode IN ('safe','standard')),
        status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed','cancelled')) DEFAULT 'queued',
        started_at TIMESTAMPTZ,
        ended_at TIMESTAMPTZ,
        tool_versions JSONB NOT NULL DEFAULT '{}'::jsonb,
        stats JSONB NOT NULL DEFAULT '{}'::jsonb,
        error TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `ALTER TABLE asv_scan_run
       ADD COLUMN IF NOT EXISTS scan_mode TEXT NOT NULL DEFAULT 'safe'`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_scan_run_asset_idx ON asv_scan_run (asset_id, created_at DESC)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_scan_run_status_idx ON asv_scan_run (status, updated_at DESC)`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS asv_finding (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        asset_id UUID NOT NULL REFERENCES asv_asset(id) ON DELETE CASCADE,
        scan_run_id UUID REFERENCES asv_scan_run(id) ON DELETE SET NULL,
        fingerprint TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'info',
        confidence TEXT NOT NULL DEFAULT 'medium',
        tool TEXT NOT NULL DEFAULT 'unknown',
        external_id TEXT,
        affected JSONB NOT NULL DEFAULT '{}'::jsonb,
        evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
        status TEXT NOT NULL DEFAULT 'open',
        first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (asset_id, fingerprint)
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_finding_asset_idx ON asv_finding (asset_id, last_seen DESC)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_finding_severity_idx ON asv_finding (severity)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_finding_scan_run_idx ON asv_finding (scan_run_id)`);

    /**
     * AI notes for ASV: LLM-generated triage/explanations stored as immutable snapshots.
     * Written by apps/ai worker via queue. Read by API/UI.
     */
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS asv_ai_note (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        asset_id UUID NOT NULL REFERENCES asv_asset(id) ON DELETE CASCADE,
        finding_id UUID REFERENCES asv_finding(id) ON DELETE CASCADE,
        issue_id UUID REFERENCES asv_issue(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        model TEXT NOT NULL,
        prompt_version TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        output_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        output_text TEXT,
        tokens_input INT,
        tokens_output INT,
        cost_usd NUMERIC(10, 6),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (kind, finding_id, input_hash),
        UNIQUE (kind, issue_id, input_hash)
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_ai_note_asset_idx ON asv_ai_note (asset_id, created_at DESC)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_ai_note_finding_idx ON asv_ai_note (finding_id, created_at DESC)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_ai_note_issue_idx ON asv_ai_note (issue_id, created_at DESC)`);

    /**
     * Issues = агрегированные проблемы поверх findings.
     * Ключ issue_key сейчас совпадает с finding.fingerprint (стабильный дедуп).
     */
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS asv_issue (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        asset_id UUID NOT NULL REFERENCES asv_asset(id) ON DELETE CASCADE,
        issue_key TEXT NOT NULL,
        title TEXT NOT NULL,
        tool TEXT NOT NULL DEFAULT 'unknown',
        external_id TEXT,
        endpoint_key TEXT,
        severity TEXT NOT NULL DEFAULT 'info',
        confidence TEXT NOT NULL DEFAULT 'medium',
        status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved','accepted','false_positive')),
        first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_scan_run_id UUID REFERENCES asv_scan_run(id) ON DELETE SET NULL,
        occurrences INT NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
        fix_guidance JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (asset_id, issue_key)
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_issue_asset_idx ON asv_issue (asset_id, last_seen DESC)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_issue_status_idx ON asv_issue (status, last_seen DESC)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_issue_severity_idx ON asv_issue (severity)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS asv_issue_endpoint_idx ON asv_issue (endpoint_key)`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS asv_port_observation (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        asset_id UUID NOT NULL REFERENCES asv_asset(id) ON DELETE CASCADE,
        scan_run_id UUID REFERENCES asv_scan_run(id) ON DELETE SET NULL,
        target TEXT NOT NULL,
        ip INET,
        port INT NOT NULL CHECK (port > 0 AND port <= 65535),
        transport TEXT NOT NULL DEFAULT 'tcp' CHECK (transport IN ('tcp')),
        state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','closed','filtered','unknown')),
        latency_ms INT,
        evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
        observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS asv_port_observation_asset_idx ON asv_port_observation (asset_id, observed_at DESC)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS asv_port_observation_scan_idx ON asv_port_observation (scan_run_id, observed_at DESC)`
    );

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS asv_http_observation (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        asset_id UUID NOT NULL REFERENCES asv_asset(id) ON DELETE CASCADE,
        scan_run_id UUID REFERENCES asv_scan_run(id) ON DELETE SET NULL,
        url TEXT NOT NULL,
        final_url TEXT,
        status INT,
        title TEXT,
        server TEXT,
        headers JSONB NOT NULL DEFAULT '{}'::jsonb,
        tech JSONB NOT NULL DEFAULT '[]'::jsonb,
        latency_ms INT,
        evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
        observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS asv_http_observation_asset_idx ON asv_http_observation (asset_id, observed_at DESC)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS asv_http_observation_scan_idx ON asv_http_observation (scan_run_id, observed_at DESC)`
    );

    // --- Nuclei readiness: artifacts + template metadata cache (optional) ---
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS asv_scan_artifact (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        scan_run_id UUID NOT NULL REFERENCES asv_scan_run(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('nuclei.jsonl','nuclei.stdout','nuclei.stderr','scanner.log')),
        bytes INT NOT NULL DEFAULT 0,
        sha256 TEXT,
        storage TEXT NOT NULL DEFAULT 'inline' CHECK (storage IN ('inline')),
        content_text TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS asv_scan_artifact_scan_idx ON asv_scan_artifact (scan_run_id, created_at DESC)`
    );

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS asv_nuclei_template (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        template_id TEXT NOT NULL UNIQUE,
        name TEXT,
        severity TEXT,
        tags TEXT[],
        description TEXT,
        reference TEXT[],
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );

    await this.db.query(`CREATE EXTENSION IF NOT EXISTS pg_trgm`);
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_cve_id_lower_trgm_idx ON cve USING gin (lower(cve_id) gin_trgm_ops)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_raw_lower_text_trgm_idx ON cve USING gin (lower(raw::text) gin_trgm_ops)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_vendor_product_vendor_lower_trgm_idx ON cve_vendor_product USING gin (lower(vendor) gin_trgm_ops)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_vendor_product_product_lower_trgm_idx ON cve_vendor_product USING gin (lower(COALESCE(product, '')) gin_trgm_ops)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_vendor_product_vendor_key_lower_trgm_idx ON cve_vendor_product USING gin (lower(vendor_key) gin_trgm_ops)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_vendor_product_product_key_norm_lower_trgm_idx ON cve_vendor_product USING gin (lower(product_key_norm) gin_trgm_ops)`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS enrichment_ai_cve_id_idx ON enrichment_ai (cve_id)`);
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS enrichment_ai_output_text_lower_trgm_idx ON enrichment_ai USING gin (lower(COALESCE(output_text, '')) gin_trgm_ops)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS enrichment_ai_output_json_text_lower_trgm_idx ON enrichment_ai USING gin (lower(output_json::text) gin_trgm_ops)`
    );
  }

  /** Демо-строки patch management — видны сразу; при конфликте обновляются заголовок и описание (русский текст). */
  private async seedVendorAdvisoryDemoRows() {
    await this.db.query(`
      INSERT INTO vendor_advisory (dedupe_key, feed_url, vendor_slug, title, link, summary, published_at, cve_ids, raw_item)
      VALUES
        (
          'seed:patch-demo:debian-1',
          'https://www.debian.org/security/dsa?format=rss',
          'debian',
          'DSA-5924-1: ядро Linux — обновление безопасности',
          'https://www.debian.org/security/2025/dsa-5924',
          'Гонки и потенциальные ошибки работы с памятью в сетевом стеке ядра Linux; рекомендуется обновление на серверах.',
          now() - interval '3 days',
          ARRAY['CVE-2024-56605', 'CVE-2024-56606']::text[],
          '{"seed": true, "demo": true}'::jsonb
        ),
        (
          'seed:patch-demo:ubuntu-1',
          'https://ubuntu.com/security/notices/rss.xml',
          'ubuntu',
          'USN-7692-1: уязвимость OpenSSL',
          'https://ubuntu.com/security/notices/USN-7692-1',
          'Обновление OpenSSL: устранение рисков побочного канала по времени и ошибок обработки сертификатов.',
          now() - interval '5 days',
          ARRAY['CVE-2024-9143']::text[],
          '{"seed": true, "demo": true}'::jsonb
        ),
        (
          'seed:patch-demo:microsoft-1',
          'https://api.msrc.microsoft.com/update-guide/rss',
          'microsoft',
          'CVE-2026-5160 — Windows: утечка информации в ядре',
          'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-5160',
          'Исправление доступно через Центр обновления Windows и WSUS; может потребоваться перезагрузка.',
          now() - interval '1 day',
          ARRAY['CVE-2026-5160']::text[],
          '{"seed": true, "demo": true}'::jsonb
        ),
        (
          'seed:patch-demo:cisa-1',
          'https://www.cisa.gov/uscert/ncas/current-activity.xml',
          'cisa_activity',
          'CISA: известные эксплуатируемые уязвимости в каталоге KEV',
          'https://www.cisa.gov/news-events/cybersecurity-advisories',
          'Федеральным органам необходимо устранить уязвимости в установленные сроки по обязательным директивам.',
          now() - interval '2 days',
          ARRAY['CVE-2024-17088', 'CVE-2024-20353']::text[],
          '{"seed": true, "demo": true}'::jsonb
        ),
        (
          'seed:patch-demo:aws-1',
          'https://aws.amazon.com/security/security-bulletins/rss/feed/',
          'aws',
          'AWS-2025-023: обработка ICMPv6 во встроенных стеках TCP',
          'https://aws.amazon.com/security/security-bulletins/rss/aws-2025-023/',
          'Проверьте развёртывания IoT и FreeRTOS-Plus-TCP; перейдите на поддерживаемые версии.',
          now() - interval '7 days',
          ARRAY['CVE-2025-11616', 'CVE-2025-11617']::text[],
          '{"seed": true, "demo": true}'::jsonb
        ),
        (
          'seed:patch-demo:oracle-1',
          'https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml',
          'oracle',
          'Oracle: критическое обновление (CPU) — БД и Fusion Middleware',
          'https://www.oracle.com/security-alerts/',
          'В состав входят исправления, в том числе для уязвимостей, эксплуатируемых удалённо без аутентификации.',
          now() - interval '10 days',
          ARRAY['CVE-2024-20913', 'CVE-2024-20918']::text[],
          '{"seed": true, "demo": true}'::jsonb
        ),
        (
          'seed:patch-demo:redhat-1',
          'https://www.redhat.com/en/rss/blog/security',
          'redhat',
          'Red Hat: рекомендации по усилению OpenShift 4.18',
          'https://www.redhat.com/en/blog',
          'Обновления кластера и каналов операторов для устранения CVE в регулируемых средах.',
          now() - interval '4 days',
          ARRAY['CVE-2024-37371']::text[],
          '{"seed": true, "demo": true}'::jsonb
        ),
        (
          'seed:patch-demo:gcp-1',
          'https://cloud.google.com/feeds/google-cloud-security-bulletins.xml',
          'google_cloud',
          'GCP-2025-042: обновление образов узлов GKE (containerd, runc)',
          'https://cloud.google.com/anthos/clusters/docs/security-bulletins',
          'Обновите пулы узлов до рекомендуемых версий до окна обслуживания.',
          now() - interval '6 days',
          ARRAY['CVE-2024-9676']::text[],
          '{"seed": true, "demo": true}'::jsonb
        ),
        (
          'seed:patch-demo:suse-1',
          'https://security.suse.com/rss.xml',
          'suse',
          'SUSE-SU-2025: обновление systemd и PAM',
          'https://www.suse.com/support/update/',
          'Пакет исправлений для стека аутентификации в SUSE Linux Enterprise 15 SP6.',
          now() - interval '8 days',
          ARRAY['CVE-2024-24557']::text[],
          '{"seed": true, "demo": true}'::jsonb
        ),
        (
          'seed:patch-demo:k8s-1',
          'https://kubernetes.io/feed.xml',
          'kubernetes',
          'Kubernetes: жизненный цикл ingress-контроллера и поддерживаемые релизы',
          'https://kubernetes.io/blog/',
          'Планируйте обновления до удаления API; после изменений проверьте политики admission.',
          now() - interval '12 hours',
          ARRAY['CVE-2025-1974']::text[],
          '{"seed": true, "demo": true}'::jsonb
        )
      ON CONFLICT (dedupe_key) DO UPDATE SET
        feed_url = EXCLUDED.feed_url,
        vendor_slug = EXCLUDED.vendor_slug,
        title = EXCLUDED.title,
        link = EXCLUDED.link,
        summary = EXCLUDED.summary,
        published_at = EXCLUDED.published_at,
        cve_ids = EXCLUDED.cve_ids,
        raw_item = EXCLUDED.raw_item
    `);
  }
}

