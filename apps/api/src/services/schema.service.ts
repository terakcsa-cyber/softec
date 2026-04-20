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

