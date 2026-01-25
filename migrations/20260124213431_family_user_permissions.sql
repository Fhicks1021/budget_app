CREATE TABLE families (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    created_by_user INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE family_members (
    id          SERIAL PRIMARY KEY,
    family_id   INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('adult', 'dependent')),
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'invited', 'removed')),
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (family_id, user_id)
);

CREATE INDEX idx_family_members_user_id ON family_members(user_id);
CREATE INDEX idx_family_members_family_id ON family_members(family_id);
