-- Create families table: one row per family unit
CREATE TABLE families (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    created_by_user INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Each user can belong to one or more families (we can restrict later if needed)
CREATE TABLE family_members (
    id          SERIAL PRIMARY KEY,
    family_id   INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK (role IN ('adult', 'dependent')),
    status      TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'invited', 'removed')),
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- You probably don’t want the same user added twice to the same family
    UNIQUE (family_id, user_id)
);

-- Helpful indexes for lookups
CREATE INDEX idx_family_members_user_id ON family_members(user_id);
CREATE INDEX idx_family_members_family_id ON family_members(family_id);
