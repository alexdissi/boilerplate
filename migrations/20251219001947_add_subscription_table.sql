-- +goose Up
CREATE TABLE subscriptions (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    cus_id VARCHAR(100) UNIQUE,
    plan TEXT NOT NULL DEFAULT 'FREE',
    license_count SMALLINT DEFAULT 0,
    paid BOOLEAN DEFAULT false,
    status VARCHAR(50) DEFAULT 'ACTIVE',
    sub_id VARCHAR(100) UNIQUE,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_subscriptions_cus_id ON subscriptions(cus_id);

-- +goose Down
DROP TABLE IF EXISTS subscriptions;
