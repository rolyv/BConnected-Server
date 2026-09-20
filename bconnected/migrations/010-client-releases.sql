BEGIN;
CREATE SCHEMA IF NOT EXISTS signal;
CREATE TABLE IF NOT EXISTS signal.client_releases (
  platform text NOT NULL,
  version text NOT NULL,
  released_at bigint NOT NULL,
  expires_at bigint NOT NULL,
  PRIMARY KEY (platform, version)
);
COMMENT ON TABLE signal.client_releases IS 'Operator-maintained client release metadata used for metrics version labels';
COMMENT ON COLUMN signal.client_releases.released_at IS 'Release time as integral Unix epoch seconds';
COMMENT ON COLUMN signal.client_releases.expires_at IS 'Metrics-label expiration as integral Unix epoch seconds; readers retain expired rows';
COMMIT;
