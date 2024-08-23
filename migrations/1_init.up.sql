CREATE TABLE IF NOT EXISTS users(
    uid serial PRIMARY KEY,
    name TEXT NOT NULL,
    login TEXT NOT NULL,
    password TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS login_id ON users (login);

CREATE TABLE IF NOT EXISTS books(
    bid serial PRIMARY KEY,
    lable TEXT NOT NULL,
    author TEXT NOT NULL,
    delete BOOLEAN NOT NULL DEFAULT false,
    uid integer NOT NULL
);