-- Baseline migration. Add the team's schema as V2__..., V3__... (never edit a migration once shared).
-- Seed data also goes in migrations so a fresh database is complete on first start.
CREATE TABLE IF NOT EXISTS app_metadata (
    key   VARCHAR(64) PRIMARY KEY,
    value VARCHAR(256) NOT NULL
);

INSERT INTO app_metadata (key, value) VALUES ('service', 'APP04 payments') ON CONFLICT DO NOTHING;
