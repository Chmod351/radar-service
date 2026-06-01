const tables = `
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_root TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS infrastructure (
    ip TEXT PRIMARY KEY,
    asn TEXT,
    asn_owner TEXT,
    country TEXT,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS whois_data (
    root_domain TEXT PRIMARY KEY,
    registrar TEXT,
    creationDate TEXT,
    expirationDate TEXT,
    nameServers TEXT,
    raw TEXT,
    emails TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_status TEXT DEFAULT 'PENDING',
    host TEXT,
    ip TEXT,
    cdn INTEGER,
    url TEXT,
    status_code INTEGER,
    scan_id INTEGER,
    root_domain TEXT,
    title TEXT,
    webserver TEXT,
    action INTEGER,
    app_status INTEGER,
    hsts BOOLEAN,
    csp BOOLEAN,
    xfo BOOLEAN,
    nosniff BOOLEAN,
    FOREIGN KEY(ip) REFERENCES infrastructure(ip),
    FOREIGN KEY(root_domain) REFERENCES whois_data(root_domain),
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    port INTEGER,
    protocol INTEGER,
    transport INTEGER,
    service TEXT,
    version TEXT,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS http_stack (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    name TEXT,
    version TEXT,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);
`;

export default tables;
