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
        role TEXT NOT NULL DEFAULT 'analyst',
        enabled BOOLEAN NOT NULL DEFAULT true,
        must_change_password BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(`ALTER TABLE auth_user ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'analyst'`);
    await this.db.query(`ALTER TABLE auth_user ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true`);
    await this.db.query(
      `ALTER TABLE auth_user ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false`
    );
    await this.db.query(`ALTER TABLE auth_user DROP CONSTRAINT IF EXISTS auth_user_role_check`);
    await this.db.query(
      `ALTER TABLE auth_user
         ADD CONSTRAINT auth_user_role_check CHECK (role IN ('admin', 'analyst', 'viewer'))`
    );
    await this.db.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS auth_user_email_lower_idx ON auth_user (lower(email))`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS auth_user_role_idx ON auth_user (role)`);
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
      `CREATE TABLE IF NOT EXISTS epss_score_history (
        cve_id TEXT NOT NULL,
        score DOUBLE PRECISION NOT NULL,
        percentile DOUBLE PRECISION,
        scored_at DATE NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (cve_id, scored_at)
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS epss_score_history_cve_scored_idx ON epss_score_history (cve_id, scored_at DESC)`
    );

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS vulncheck_kev (
        cve_id TEXT PRIMARY KEY,
        date_added TIMESTAMPTZ,
        cisa_date_added TIMESTAMPTZ,
        vckev_only BOOLEAN NOT NULL DEFAULT false,
        ransomware_use TEXT,
        evidence_count INT NOT NULL DEFAULT 0,
        xdb_url TEXT,
        raw JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS vulncheck_kev_date_added_idx ON vulncheck_kev (date_added DESC NULLS LAST)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS vulncheck_kev_vckev_only_idx ON vulncheck_kev (vckev_only) WHERE vckev_only = true`
    );

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS cve_exploit_signal (
        id BIGSERIAL PRIMARY KEY,
        cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
        signal_type TEXT NOT NULL,
        source TEXT NOT NULL,
        url TEXT,
        title TEXT,
        confidence TEXT NOT NULL DEFAULT 'medium',
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        raw JSONB
      )`
    );
    await this.db.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS cve_exploit_signal_uq ON cve_exploit_signal (cve_id, signal_type, source, COALESCE(url, ''))`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_exploit_signal_cve_idx ON cve_exploit_signal (cve_id)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_exploit_signal_type_idx ON cve_exploit_signal (signal_type)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_exploit_signal_last_seen_idx ON cve_exploit_signal (last_seen_at DESC)`
    );

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS cve_exploit_intel (
        cve_id TEXT PRIMARY KEY REFERENCES cve(cve_id) ON DELETE CASCADE,
        epss_score DOUBLE PRECISION,
        epss_percentile DOUBLE PRECISION,
        epss_delta_7d DOUBLE PRECISION,
        epss_spike BOOLEAN NOT NULL DEFAULT false,
        cisa_kev BOOLEAN NOT NULL DEFAULT false,
        vulncheck_kev BOOLEAN NOT NULL DEFAULT false,
        vckev_only BOOLEAN NOT NULL DEFAULT false,
        has_poc BOOLEAN NOT NULL DEFAULT false,
        has_nuclei BOOLEAN NOT NULL DEFAULT false,
        has_public_exploit BOOLEAN NOT NULL DEFAULT false,
        exploit_ref_count INT NOT NULL DEFAULT 0,
        tg_mentions_24h INT NOT NULL DEFAULT 0,
        advisory_mentions_7d INT NOT NULL DEFAULT 0,
        intel_updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_exploit_intel_spike_idx ON cve_exploit_intel (epss_spike) WHERE epss_spike = true`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS cve_exploit_intel_vckev_only_idx ON cve_exploit_intel (vckev_only) WHERE vckev_only = true`
    );

    /** Связки БДУ ФСТЭК ↔ CVE (накапливаются при обогащении ленты, если CVE уже в `cve`). */
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS cve_bdu_link (
        cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
        bdu_id TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (cve_id, bdu_id)
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS cve_bdu_link_bdu_idx ON cve_bdu_link (bdu_id)`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS bdu_vuln (
        bdu_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        software_names TEXT,
        vendors TEXT,
        cve_ids TEXT[] NOT NULL DEFAULT '{}',
        severity TEXT,
        severity_level INT NOT NULL DEFAULT 0,
        cvss_score DOUBLE PRECISION,
        cvss_vector TEXT,
        identify_date TEXT,
        publication_date TEXT,
        last_upd_date TEXT,
        identify_year INT,
        solution TEXT,
        status TEXT,
        exploit_status TEXT,
        fix_status TEXT,
        has_exploit BOOLEAN NOT NULL DEFAULT false,
        has_fix BOOLEAN NOT NULL DEFAULT false,
        sources TEXT,
        fstec_url TEXT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS bdu_vuln_year_idx ON bdu_vuln (identify_year DESC NULLS LAST)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS bdu_vuln_cvss_idx ON bdu_vuln (cvss_score DESC NULLS LAST)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS bdu_vuln_publication_date_idx ON bdu_vuln (publication_date)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS bdu_vuln_last_upd_date_idx ON bdu_vuln (last_upd_date)`);
    await this.db.query(`CREATE INDEX IF NOT EXISTS bdu_vuln_cve_ids_gin ON bdu_vuln USING gin (cve_ids)`);
    await this.db.query(`DROP INDEX IF EXISTS bdu_vuln_publication_ts_idx`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS enrichment_bdu (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        bdu_id TEXT NOT NULL REFERENCES bdu_vuln(bdu_id) ON DELETE CASCADE,
        model TEXT NOT NULL,
        prompt_version TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        output_json JSONB NOT NULL,
        output_text TEXT,
        tokens_input INT,
        tokens_output INT,
        cost_usd NUMERIC(10, 6),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (bdu_id, model, prompt_version, input_hash)
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS enrichment_bdu_bdu_id_idx ON enrichment_bdu (bdu_id)`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS fstec_bulletin (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT,
        reference_no TEXT,
        source_filename TEXT,
        plain_text TEXT NOT NULL,
        parsed_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        status TEXT NOT NULL DEFAULT 'parsed',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS fstec_bulletin_created_idx ON fstec_bulletin (created_at DESC)`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS fstec_bulletin_analysis (
        bulletin_id UUID PRIMARY KEY REFERENCES fstec_bulletin(id) ON DELETE CASCADE,
        output_json JSONB,
        output_text TEXT,
        model TEXT,
        prompt_version TEXT,
        input_hash TEXT,
        tokens_input INT,
        tokens_output INT,
        status TEXT NOT NULL DEFAULT 'pending',
        error_text TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
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
          CHECK (status IN ('new','in_progress','closed')),
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
    await this.db.query(
      `UPDATE vuln_task
          SET status = CASE
            WHEN status IN ('needs_info', 'fixing', 'mitigated') THEN 'in_progress'
            WHEN status IN ('risk_accepted', 'not_applicable', 'closed') THEN 'closed'
            ELSE 'new'
          END
        WHERE status NOT IN ('new', 'in_progress', 'closed')`
    );
    await this.db.query(
      `UPDATE vuln_task
          SET closed_at = CASE
            WHEN status = 'closed' THEN COALESCE(closed_at, now())
            ELSE NULL
          END`
    );
    await this.db.query(`ALTER TABLE vuln_task DROP CONSTRAINT IF EXISTS vuln_task_status_check`);
    await this.db.query(
      `ALTER TABLE vuln_task
         ADD CONSTRAINT vuln_task_status_check CHECK (status IN ('new', 'in_progress', 'closed'))`
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
      `WITH extracted AS (
         SELECT DISTINCT t.id AS task_id,
                upper((m.match)[1]) AS cve_id,
                t.vendor_display,
                t.vendor_key,
                t.product_display,
                t.product_key_norm
           FROM vuln_task t
     CROSS JOIN LATERAL regexp_matches(
                concat_ws(' ', t.title, t.notes_md, t.evidence),
                '(CVE-[0-9]{4}-[0-9]{4,})',
                'gi'
              ) AS m(match)
          WHERE NOT EXISTS (SELECT 1 FROM vuln_task_cve l WHERE l.task_id = t.id)
       )
       INSERT INTO cve (cve_id, source, raw)
       SELECT e.cve_id,
              'task.backfill',
              jsonb_build_object(
                'source', 'task.backfill',
                'placeholder', true,
                'cve', jsonb_build_object('id', e.cve_id)
              )
         FROM extracted e
       ON CONFLICT (cve_id) DO NOTHING`
    );
    await this.db.query(
      `WITH extracted AS (
         SELECT DISTINCT t.id AS task_id,
                upper((m.match)[1]) AS cve_id
           FROM vuln_task t
     CROSS JOIN LATERAL regexp_matches(
                concat_ws(' ', t.title, t.notes_md, t.evidence),
                '(CVE-[0-9]{4}-[0-9]{4,})',
                'gi'
              ) AS m(match)
          WHERE NOT EXISTS (SELECT 1 FROM vuln_task_cve l WHERE l.task_id = t.id)
       )
       INSERT INTO vuln_task_cve (task_id, cve_id, note)
       SELECT task_id, cve_id, 'auto-linked from task text'
         FROM extracted
       ON CONFLICT DO NOTHING`
    );
    await this.db.query(
      `WITH extracted AS (
         SELECT DISTINCT upper((m.match)[1]) AS cve_id,
                t.vendor_display,
                t.vendor_key,
                t.product_display,
                t.product_key_norm
           FROM vuln_task t
     CROSS JOIN LATERAL regexp_matches(
                concat_ws(' ', t.title, t.notes_md, t.evidence),
                '(CVE-[0-9]{4}-[0-9]{4,})',
                'gi'
              ) AS m(match)
          WHERE t.vendor_display <> '' AND t.vendor_key <> ''
       )
       INSERT INTO cve_vendor_product (cve_id, vendor, product, vendor_key, product_key, product_key_norm, source)
       SELECT e.cve_id, e.vendor_display, NULLIF(e.product_display, ''), e.vendor_key, NULLIF(e.product_display, ''), e.product_key_norm, 'task.backfill'
         FROM extracted e
       ON CONFLICT (cve_id, vendor_key, product_key_norm) DO NOTHING`
    );

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

    // --- VOC triage (team-wide operational queue state) ---
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS voc_triage (
        ref_key TEXT PRIMARY KEY,
        source TEXT NOT NULL CHECK (source IN ('cve','bdu','tg')),
        ref_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open'
          CHECK (status IN ('open','claimed','done','dismissed')),
        claimed_by_user_id UUID REFERENCES auth_user(id) ON DELETE SET NULL,
        claimed_by_email TEXT,
        updated_by_user_id UUID REFERENCES auth_user(id) ON DELETE SET NULL,
        updated_by_email TEXT,
        voc_score INT NOT NULL DEFAULT 0 CHECK (voc_score >= 0 AND voc_score <= 100),
        voc_priority TEXT NOT NULL DEFAULT 'p4'
          CHECK (voc_priority IN ('p1','p2','p3','p4')),
        voc_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
        title TEXT NOT NULL DEFAULT '',
        meta JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS voc_triage_status_updated_idx ON voc_triage (status, updated_at DESC)`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS voc_triage_source_idx ON voc_triage (source)`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS voc_watchlist (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        kind TEXT NOT NULL CHECK (kind IN ('vendor','product','keyword')),
        value TEXT NOT NULL,
        label TEXT NOT NULL DEFAULT '',
        active BOOLEAN NOT NULL DEFAULT true,
        created_by_user_id UUID REFERENCES auth_user(id) ON DELETE SET NULL,
        created_by_email TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        CONSTRAINT voc_watchlist_kind_value_uq UNIQUE (kind, value)
      )`
    );
    await this.db.query(
      `CREATE UNIQUE INDEX IF NOT EXISTS voc_watchlist_kind_value_uq ON voc_watchlist (kind, value)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS voc_watchlist_active_idx ON voc_watchlist (active, updated_at DESC)`
    );
    await this.db.query(`
      DO $$ BEGIN
        ALTER TABLE voc_watchlist ADD CONSTRAINT voc_watchlist_kind_value_uq UNIQUE (kind, value);
      EXCEPTION
        WHEN duplicate_object THEN NULL;
        WHEN duplicate_table THEN NULL;
      END $$`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS voc_case (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open'
          CHECK (status IN ('open','in_progress','resolved','cancelled')),
        dedup_key TEXT NOT NULL,
        primary_ref_key TEXT NOT NULL,
        assignee_user_id UUID REFERENCES auth_user(id) ON DELETE SET NULL,
        assignee_email TEXT,
        sla_due_at TIMESTAMPTZ,
        voc_priority TEXT NOT NULL DEFAULT 'p4'
          CHECK (voc_priority IN ('p1','p2','p3','p4')),
        task_id UUID REFERENCES vuln_task(id) ON DELETE SET NULL,
        created_by_user_id UUID REFERENCES auth_user(id) ON DELETE SET NULL,
        created_by_email TEXT,
        meta JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS voc_case_status_sla_idx ON voc_case (status, sla_due_at ASC)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS voc_case_dedup_idx ON voc_case (dedup_key, updated_at DESC)`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS voc_case_ref (
        case_id UUID NOT NULL REFERENCES voc_case(id) ON DELETE CASCADE,
        ref_key TEXT NOT NULL,
        source TEXT NOT NULL CHECK (source IN ('cve','bdu','tg')),
        ref_id TEXT NOT NULL,
        added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (case_id, ref_key)
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS voc_case_ref_ref_key_idx ON voc_case_ref (ref_key)`);

    await this.db.query(`ALTER TABLE voc_case ADD COLUMN IF NOT EXISTS outcome TEXT`);
    await this.db.query(`ALTER TABLE voc_case ADD COLUMN IF NOT EXISTS outcome_notes TEXT`);
    await this.db.query(`ALTER TABLE voc_case ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ`);
    await this.db.query(`ALTER TABLE voc_case ADD COLUMN IF NOT EXISTS playbook JSONB NOT NULL DEFAULT '{}'::jsonb`);
    await this.db.query(
      `ALTER TABLE voc_case DROP CONSTRAINT IF EXISTS voc_case_outcome_check`
    );
    // In dev multiple API instances can race on schema init: both DROP, then both ADD → one gets 42710.
    try {
      await this.db.query(
        `ALTER TABLE voc_case ADD CONSTRAINT voc_case_outcome_check
           CHECK (outcome IS NULL OR outcome IN (
             'not_affected','exposed','monitoring','patched','accepted_risk','needs_more_info'
           ))`
      );
    } catch (e: any) {
      if (String(e?.code ?? "") !== "42710") throw e;
    }
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS voc_case_evidence (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        case_id UUID NOT NULL REFERENCES voc_case(id) ON DELETE CASCADE,
        author_email TEXT,
        body TEXT NOT NULL,
        url TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS voc_case_evidence_case_idx ON voc_case_evidence (case_id, created_at DESC)`
    );

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS voc_alert_rule (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        active BOOLEAN NOT NULL DEFAULT true,
        condition TEXT NOT NULL
          CHECK (condition IN ('p1_open','sla_breach','watchlist_p1','case_exposed')),
        channel TEXT NOT NULL DEFAULT 'telegram'
          CHECK (channel IN ('telegram','webhook')),
        webhook_url TEXT,
        config JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS voc_alert_fired (
        rule_id UUID NOT NULL REFERENCES voc_alert_rule(id) ON DELETE CASCADE,
        dedup_key TEXT NOT NULL,
        fired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (rule_id, dedup_key)
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS voc_alert_fired_at_idx ON voc_alert_fired (fired_at DESC)`);
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS voc_handover (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        author_email TEXT,
        window_hours INT NOT NULL DEFAULT 8,
        snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
        notes TEXT,
        markdown TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );
    await this.db.query(`CREATE INDEX IF NOT EXISTS voc_handover_created_idx ON voc_handover (created_at DESC)`);

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS app_integration_settings (
        key TEXT PRIMARY KEY,
        value JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`
    );

    await this.db.query(
      `CREATE TABLE IF NOT EXISTS mpvm_asset (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        external_id TEXT NOT NULL,
        hostname TEXT,
        ip_address TEXT,
        os_name TEXT,
        os_version TEXT,
        display_name TEXT NOT NULL,
        raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (external_id)
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS mpvm_asset_last_synced_idx ON mpvm_asset (last_synced_at DESC)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS mpvm_asset_ip_idx ON mpvm_asset (ip_address) WHERE ip_address IS NOT NULL`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS mpvm_asset_software (
        asset_external_id TEXT NOT NULL REFERENCES mpvm_asset(external_id) ON DELETE CASCADE,
        software_key TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT 'software' CHECK (kind IN ('software', 'package')),
        name TEXT NOT NULL,
        version TEXT,
        vendor TEXT,
        install_path TEXT,
        raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (asset_external_id, software_key)
      )`
    );
    await this.db.query(
      `ALTER TABLE mpvm_asset_software
       ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'software'`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS mpvm_asset_software_name_idx ON mpvm_asset_software (lower(name))`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS mpvm_asset_software_asset_idx ON mpvm_asset_software (asset_external_id)`
    );
    await this.db.query(
      `CREATE TABLE IF NOT EXISTS mpvm_asset_vulnerability (
        asset_external_id TEXT NOT NULL REFERENCES mpvm_asset(external_id) ON DELETE CASCADE,
        vuln_key TEXT NOT NULL,
        cve_id TEXT,
        title TEXT,
        severity TEXT,
        cvss_score DOUBLE PRECISION,
        status TEXT,
        fix_available BOOLEAN,
        solution TEXT,
        affected_software_key TEXT,
        affected_software_name TEXT,
        affected_software_version TEXT,
        raw_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (asset_external_id, vuln_key)
      )`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS mpvm_asset_vulnerability_cve_idx ON mpvm_asset_vulnerability (cve_id) WHERE cve_id IS NOT NULL`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS mpvm_asset_vulnerability_asset_idx ON mpvm_asset_vulnerability (asset_external_id)`
    );
    await this.db.query(
      `CREATE INDEX IF NOT EXISTS mpvm_asset_vulnerability_software_idx ON mpvm_asset_vulnerability (lower(affected_software_name)) WHERE affected_software_name IS NOT NULL`
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

