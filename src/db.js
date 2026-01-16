const Database = require('better-sqlite3');
const fs = require('node:fs');
const path = require('node:path');
const config = require('./config');

const DB_PATH = config.dbPath;

// Demo users - only used in development mode and only if there is no existing table
const demo_users = config.isDevelopment ? config.demoUsers : null;


// Permission levels
const PERMISSIONS = {
    READ: 1,
    WRITE: 2,
    ADMIN: 3
};

function create_db_if_missing() {
    // Check if database file exists
    if (fs.existsSync(DB_PATH)) {
        return;
    }

    // Ensure directory exists
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }

    // Create database and tables
    const db = new Database(DB_PATH);

    try {
        // Enable foreign key constraints
        db.exec('PRAGMA foreign_keys = ON');

        // Create USERS table (production: OIDC sub, development: username)
        db.exec(`
      CREATE TABLE USERS (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        identifier TEXT NOT NULL UNIQUE,
        password TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
        db.exec('CREATE INDEX idx_users_identifier ON USERS(identifier)');

        // Create ENTITLEMENTS table (LBR URNs from eduPersonEntitlement claims)
        db.exec(`
      CREATE TABLE ENTITLEMENTS (
        entitlement_id INTEGER PRIMARY KEY AUTOINCREMENT,
        urn TEXT NOT NULL UNIQUE,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
        db.exec('CREATE INDEX idx_entitlements_urn ON ENTITLEMENTS(urn)');

        // Create RESOURCES table
        db.exec(`
      CREATE TABLE RESOURCES (
        resource_name TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK (type IN ('corpus', 'metadata', 'other'))
      )
    `);

        // Create GRANTS table with polymorphic foreign keys
        db.exec(`
      CREATE TABLE GRANTS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        entitlement_id INTEGER,
        resource_name TEXT NOT NULL,
        permission_level INTEGER NOT NULL CHECK (permission_level IN (1, 2, 3)),
        granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES USERS(user_id) ON DELETE CASCADE,
        FOREIGN KEY (entitlement_id) REFERENCES ENTITLEMENTS(entitlement_id) ON DELETE CASCADE,
        FOREIGN KEY (resource_name) REFERENCES RESOURCES(resource_name) ON DELETE CASCADE,
        CHECK ((user_id IS NOT NULL AND entitlement_id IS NULL) OR
               (user_id IS NULL AND entitlement_id IS NOT NULL))
      )
    `);
        db.exec('CREATE INDEX idx_grants_user ON GRANTS(user_id)');
        db.exec('CREATE INDEX idx_grants_entitlement ON GRANTS(entitlement_id)');
        db.exec('CREATE INDEX idx_grants_resource ON GRANTS(resource_name)');

        // Unique constraints: this way one (id, resource) pair should have only one access level
        db.exec('CREATE UNIQUE INDEX idx_grants_user_resource ON GRANTS(user_id, resource_name)');
        db.exec('CREATE UNIQUE INDEX idx_grants_entitlement_resource ON GRANTS(entitlement_id, resource_name)');

        // Insert demo users for development mode
        if (demo_users) {
            const stmt = db.prepare('INSERT INTO USERS (identifier, password) VALUES (?, ?)');
            for (const demo_username in demo_users) {
                stmt.run(demo_username, demo_users[demo_username].password);
            }
        }

    } finally {
        db.close();
    }
}

function get_user_password(identifier) {
    const db = new Database(DB_PATH);
    try {
        const stmt = db.prepare(`
      SELECT password FROM USERS WHERE identifier = ?`);
        const result = stmt.get(identifier);
        return result ? result.password : null;
    } finally {
        db.close()
    }
}

function user_exists(identifier) {
  const db = new Database(DB_PATH);

  try {
    const stmt = db.prepare('SELECT 1 FROM USERS WHERE identifier = ? LIMIT 1');
    const result = stmt.get(identifier);
    return result !== undefined;
  } finally {
    db.close();
  }
}

function get_user_scope(userIdentifier, entitlements = []) {
    const db = new Database(DB_PATH);

    try {
        // Build query to get grants from both user and entitlements
        let query = `
      SELECT r.resource_name, r.type, MAX(g.permission_level) as permission_level
      FROM GRANTS g
      JOIN RESOURCES r ON g.resource_name = r.resource_name
      WHERE (
        g.user_id = (SELECT user_id FROM USERS WHERE identifier = ?)
    `;

        const params = [userIdentifier];

        // Add entitlement lookups if provided
        if (entitlements.length > 0) {
            const urnPlaceholders = entitlements.map(() => '?').join(',');
            query += `
        OR g.entitlement_id IN (
          SELECT entitlement_id FROM ENTITLEMENTS WHERE urn IN (${urnPlaceholders})
        )
      `;
            params.push(...entitlements);
        }

        query += `
      )
      GROUP BY r.resource_name, r.type
    `;

        const stmt = db.prepare(query);
        const rows = stmt.all(...params);

        // Transform to scope object grouped by resource type
        const scope = {};

        for (const row of rows) {
            const scopeKey = row.type === 'corpus' ? 'corpora' : row.type;
            if (!scope[scopeKey]) {
                scope[scopeKey] = {};
            }
            scope[scopeKey][row.resource_name] = row.permission_level;
        }

        return scope;

    } finally {
        db.close();
    }
}

function get_user_scope_all_resources(userIdentifier) {
  const db = new Database(DB_PATH);

  try {
    const stmt = db.prepare(`
      SELECT r.resource_name, r.type, COALESCE(g.permission_level, 0) as permission_level
      FROM RESOURCES r
      LEFT JOIN GRANTS g ON r.resource_name = g.resource_name
        AND g.user_id = (SELECT user_id FROM USERS WHERE identifier = ?)
    `);

    const rows = stmt.all(userIdentifier);

    const scope = {};

    for (const row of rows) {
      const scopeKey = row.type === 'corpus' ? 'corpora' : row.type;
      if (!scope[scopeKey]) {
        scope[scopeKey] = {};
      }
      scope[scopeKey][row.resource_name] = row.permission_level;
    }

    return { scope };

  } finally {
    db.close();
  }
}

class ResourceExistsError extends Error {
    constructor(message, resourceName) {
        super(message);
        this.resourceName = resourceName;
    }
}

function create_resource(resource_name, resource_type) {
    if (!['corpus', 'metadata', 'other'].includes(resource_type)) {
        throw new Error('Invalid resource type. Must be corpus, metadata, or other');
    }

    const db = new Database(DB_PATH);

    try {
        // Check if resource already exists
        const checkStmt = db.prepare('SELECT COUNT(*) as count FROM RESOURCES WHERE resource_name = ?');
        const result = checkStmt.get(resource_name);
        
        if (result.count > 0) {
            throw new ResourceExistsError(`Resource '${resource_name}' already exists`);
        }
        
        const stmt = db.prepare('INSERT INTO RESOURCES (resource_name, type) VALUES (?, ?)');
        stmt.run(resource_name, resource_type);
    } finally {
        db.close();
    }
}

function delete_resource(resource_name) {
    const db = new Database(DB_PATH);
    
    try {
        const stmt = db.prepare('DELETE FROM RESOURCES WHERE resource_name = ?');
        stmt.run(resource_name);
    } finally {
        db.close();
    }
}

function resource_exists(resource_name) {
    const db = new Database(DB_PATH);

    try {
        const stmt = db.prepare('SELECT 1 FROM RESOURCES WHERE resource_name = ? LIMIT 1');
        const result = stmt.get(resource_name);
        return result !== undefined;
    } finally {
        db.close();
    }
}

function list_resources() {
    const db = new Database(DB_PATH);

    try {
        const stmt = db.prepare(`
      SELECT
        r.resource_name,
        r.type,
        COUNT(g.id) as grant_count
      FROM RESOURCES r
      LEFT JOIN GRANTS g ON r.resource_name = g.resource_name
      GROUP BY r.resource_name
      ORDER BY r.type, r.resource_name
    `);
        return stmt.all();
    } finally {
        db.close();
    }
}

function add_user(identifier) {
    const db = new Database(DB_PATH);

    try {
        const stmt = db.prepare('INSERT INTO USERS (identifier) VALUES (?)');
        stmt.run(identifier);
    } finally {
        db.close();
    }
}

function delete_user(identifier) {
    const db = new Database(DB_PATH);

    try {
        const stmt = db.prepare('DELETE FROM USERS WHERE identifier = ?');
        stmt.run(identifier);
        // Grants will be automatically deleted due to CASCADE constraint
    } finally {
        db.close();
    }
}

/**
 * Set grant for either a user or an entitlement
 * @param {object} options - {userIdentifier, entitlementUrn, resourceName, level}
 */
function set_grant({ userIdentifier, entitlementUrn, resourceName, level }) {
    if (![1, 2, 3].includes(level)) {
        throw new Error('Invalid permission level. Must be 1 (READ), 2 (WRITE), or 3 (ADMIN)');
    }

    if (!userIdentifier && !entitlementUrn) {
        throw new Error('Must specify either userIdentifier or entitlementUrn');
    }

    if (userIdentifier && entitlementUrn) {
        throw new Error('Cannot specify both userIdentifier and entitlementUrn');
    }

    const db = new Database(DB_PATH);

    try {
        if (userIdentifier) {
            const stmt = db.prepare(`
        INSERT INTO GRANTS (user_id, resource_name, permission_level)
        VALUES (
          (SELECT user_id FROM USERS WHERE identifier = ?),
          ?, ?
        )
        ON CONFLICT(user_id, resource_name)
        DO UPDATE SET permission_level = excluded.permission_level
        WHERE user_id IS NOT NULL
      `);
            stmt.run(userIdentifier, resourceName, level);
        } else {
            const stmt = db.prepare(`
        INSERT INTO GRANTS (entitlement_id, resource_name, permission_level)
        VALUES (
          (SELECT entitlement_id FROM ENTITLEMENTS WHERE urn = ?),
          ?, ?
        )
        ON CONFLICT(entitlement_id, resource_name)
        DO UPDATE SET permission_level = excluded.permission_level
        WHERE entitlement_id IS NOT NULL
      `);
            stmt.run(entitlementUrn, resourceName, level);
        }
    } finally {
        db.close();
    }
}

/**
 * Remove grant for either a user or an entitlement
 */
function remove_grant({ userIdentifier, entitlementUrn, resourceName }) {
    if (!userIdentifier && !entitlementUrn) {
        throw new Error('Must specify either userIdentifier or entitlementUrn');
    }

    const db = new Database(DB_PATH);

    try {
        if (userIdentifier) {
            const stmt = db.prepare(`
        DELETE FROM GRANTS
        WHERE user_id = (SELECT user_id FROM USERS WHERE identifier = ?)
          AND resource_name = ?
      `);
            stmt.run(userIdentifier, resourceName);
        } else {
            const stmt = db.prepare(`
        DELETE FROM GRANTS
        WHERE entitlement_id = (SELECT entitlement_id FROM ENTITLEMENTS WHERE urn = ?)
          AND resource_name = ?
      `);
            stmt.run(entitlementUrn, resourceName);
        }
    } finally {
        db.close();
    }
}

function user_is_resource_admin(userIdentifier, resourcename) {
  const db = new Database(DB_PATH);

  try {
    const stmt = db.prepare(`
      SELECT 1 FROM GRANTS g
      JOIN USERS u ON g.user_id = u.user_id
      WHERE u.identifier = ? AND g.resource_name = ? AND g.permission_level = 3
      LIMIT 1
    `);
    const result = stmt.get(userIdentifier, resourcename);
    return result !== undefined;
  } finally {
    db.close();
  }
}

// ============================================================================
// User Management
// ============================================================================

function ensure_user(identifier) {
    const db = new Database(DB_PATH);

    try {
        let stmt = db.prepare('SELECT user_id FROM USERS WHERE identifier = ?');
        let result = stmt.get(identifier);

        if (result) {
            return result.user_id;
        }

        stmt = db.prepare('INSERT INTO USERS (identifier) VALUES (?)');
        const info = stmt.run(identifier);
        return info.lastInsertRowid;

    } finally {
        db.close();
    }
}

// ============================================================================
// Entitlement Management
// ============================================================================

function create_entitlement(urn, description = null) {
    const db = new Database(DB_PATH);

    try {
        const stmt = db.prepare('INSERT INTO ENTITLEMENTS (urn, description) VALUES (?, ?)');
        const info = stmt.run(urn, description);
        return info.lastInsertRowid;
    } finally {
        db.close();
    }
}

function entitlement_exists(urn) {
    const db = new Database(DB_PATH);

    try {
        const stmt = db.prepare('SELECT 1 FROM ENTITLEMENTS WHERE urn = ? LIMIT 1');
        const result = stmt.get(urn);
        return result !== undefined;
    } finally {
        db.close();
    }
}

function list_entitlements() {
    const db = new Database(DB_PATH);

    try {
        const stmt = db.prepare(`
      SELECT
        e.entitlement_id,
        e.urn,
        e.description,
        e.created_at,
        e.updated_at,
        COUNT(g.id) as grant_count
      FROM ENTITLEMENTS e
      LEFT JOIN GRANTS g ON e.entitlement_id = g.entitlement_id
      GROUP BY e.entitlement_id
      ORDER BY e.created_at DESC
    `);
        return stmt.all();
    } finally {
        db.close();
    }
}

function update_entitlement_description(urn, description) {
    const db = new Database(DB_PATH);

    try {
        const stmt = db.prepare(`
      UPDATE ENTITLEMENTS
      SET description = ?, updated_at = CURRENT_TIMESTAMP
      WHERE urn = ?
    `);
        stmt.run(description, urn);
    } finally {
        db.close();
    }
}

function delete_entitlement(urn) {
    const db = new Database(DB_PATH);

    try {
        const stmt = db.prepare('DELETE FROM ENTITLEMENTS WHERE urn = ?');
        const result = stmt.run(urn);
        return result.changes > 0;
    } finally {
        db.close();
    }
}

function get_grants_for_entitlement(urn) {
    const db = new Database(DB_PATH);

    try {
        const stmt = db.prepare(`
      SELECT g.resource_name, g.permission_level, r.type, g.granted_at
      FROM GRANTS g
      JOIN ENTITLEMENTS e ON g.entitlement_id = e.entitlement_id
      JOIN RESOURCES r ON g.resource_name = r.resource_name
      WHERE e.urn = ?
      ORDER BY r.type, g.resource_name
    `);
        return stmt.all(urn);
    } finally {
        db.close();
    }
}

module.exports = {
    demo_users,
    create_db_if_missing,
    get_user_password,
    user_exists,
    get_user_scope,
    get_user_scope_all_resources,
    ResourceExistsError,
    create_resource,
    delete_resource,
    resource_exists,
    list_resources,
    add_user,
    delete_user,
    set_grant,
    remove_grant,
    user_is_resource_admin,
    PERMISSIONS,
    // User management
    ensure_user,
    // Entitlement management
    create_entitlement,
    entitlement_exists,
    list_entitlements,
    update_entitlement_description,
    delete_entitlement,
    get_grants_for_entitlement
};
