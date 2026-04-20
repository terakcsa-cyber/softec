-- Демо-записи для модуля patch management (видны сразу после поднятия БД).
-- При повторном применении обновляются заголовок и текст (русские описания).

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
  raw_item = EXCLUDED.raw_item;
