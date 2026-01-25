ALTER TABLE budget
ADD COLUMN family_id INTEGER REFERENCES families(id);
CREATE INDEX idx_budgets_family_id ON budget(family_id);
