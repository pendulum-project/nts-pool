-- Add up migration script here
CREATE TABLE authentication_methods (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    variant JSONB NOT NULL,
    variant_type TEXT NOT NULL GENERATED ALWAYS AS (variant->>'type') STORED,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
