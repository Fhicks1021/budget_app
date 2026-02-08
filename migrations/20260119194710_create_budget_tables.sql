-- Create main budget table
CREATE TABLE budget (
    id SERIAL PRIMARY KEY,
    paycheck NUMERIC,
    mortgage NUMERIC,
    electric NUMERIC,
    phone NUMERIC,
    internet NUMERIC,
    car_insurance NUMERIC,
    remaining NUMERIC
);

-- Create categories table linked to budget
CREATE TABLE budget_categories (
    id SERIAL PRIMARY KEY,
    budget_id INT NOT NULL REFERENCES budget(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    amount NUMERIC NOT NULL
);