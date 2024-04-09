CREATE TABLE IF NOT EXISTS User (
    username TEXT PRIMARY KEY,
    SymetricKey TEXT,
    PublicKey TEXT,
    Privilege INTEGER,
    FirstTime BOOLEAN
);
