-- +goose Up
ALTER TABLE subscriptions ADD COLUMN quantity INTEGER DEFAULT 1;

-- +goose Down
ALTER TABLE subscriptions DROP COLUMN quantity;