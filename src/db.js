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
        // Create USERS table
        db.exec(`
      CREATE TABLE USERS (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL
      )
    `);

        // Create RESOURCES table
        db.exec(`
      CREATE TABLE RESOURCES (
        resource_name TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK (type IN ('corpus', 'metadata', 'other'))
      )
    `);

        // Create GRANTS table with foreign key constraints
        db.exec(`
      CREATE TABLE GRANTS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        resource_name TEXT NOT NULL,
        permission_level INTEGER NOT NULL CHECK (permission_level IN (1, 2, 3)),
        FOREIGN KEY (username) REFERENCES USERS(username) ON DELETE CASCADE,
        FOREIGN KEY (resource_name) REFERENCES RESOURCES(resource_name) ON DELETE CASCADE,
        UNIQUE(username, resource_name)
      )
    `);

        // Enable foreign key constraints
        db.exec('PRAGMA foreign_keys = ON');

        if (demo_users) {
            const stmt = db.prepare('INSERT INTO USERS (username, password) VALUES (?, ?)');
            for (const demo_username in demo_users) {
                stmt.run(demo_username, demo_users[demo_username].password);
            }
        }
        
    } finally {
        db.close();
    }
}

function get_user_password(username) {
    const db = new Database(DB_PATH);
    try {
        const stmt = db.prepare(`
      SELECT password FROM USERS WHERE username = ?`);
        return stmt.get(username).password;
    } finally {
        db.close()
    }
}

function user_exists(username) {
  const db = new Database(DB_PATH);
  
  try {
    const stmt = db.prepare('SELECT 1 FROM USERS WHERE username = ? LIMIT 1');
    const result = stmt.get(username);
    return result !== undefined;
  } finally {
    db.close();
  }
}

function get_user_scope(username) {
    const db = new Database(DB_PATH);
    
    try {
        const stmt = db.prepare(`
      SELECT r.resource_name, r.type, g.permission_level
      FROM GRANTS g
      JOIN RESOURCES r ON g.resource_name = r.resource_name
      WHERE g.username = ?
    `);
        
        const rows = stmt.all(username);
        
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

function get_user_scope_all_resources(username) {
  const db = new Database(DB_PATH);
  
  try {
    const stmt = db.prepare(`
      SELECT r.resource_name, r.type, COALESCE(g.permission_level, 0) as permission_level
      FROM RESOURCES r
      LEFT JOIN GRANTS g ON r.resource_name = g.resource_name AND g.username = ?
    `);
    
    const rows = stmt.all(username);
    
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

function add_user(username) {
    const db = new Database(DB_PATH);
    
    try {
        const stmt = db.prepare('INSERT INTO USERS (username) VALUES (?)');
        stmt.run(username);
    } finally {
        db.close();
    }
}

function delete_user(username) {
    const db = new Database(DB_PATH);
    
    try {
        const stmt = db.prepare('DELETE FROM USERS WHERE username = ?');
        stmt.run(username);
        // Grants will be automatically deleted due to CASCADE constraint
    } finally {
        db.close();
    }
}

function set_grant(user, resource_name, level) {
    if (![1, 2, 3].includes(level)) {
        throw new Error('Invalid permission level. Must be 1 (READ), 2 (WRITE), or 3 (ADMIN)');
    }

    const db = new Database(DB_PATH);
    
    try {
        const stmt = db.prepare(`
      INSERT INTO GRANTS (username, resource_name, permission_level) 
      VALUES (?, ?, ?)
      ON CONFLICT(username, resource_name) 
      DO UPDATE SET permission_level = excluded.permission_level
    `);
        stmt.run(user, resource_name, level);
    } finally {
        db.close();
    }
}

function remove_grant(user, resource_name) {
    const db = new Database(DB_PATH);
    
    try {
        const stmt = db.prepare('DELETE FROM GRANTS WHERE username = ? AND resource_name = ?');
        stmt.run(user, resource_name);
    } finally {
        db.close();
    }
}

function user_is_resource_admin(username, resourcename) {
  const db = new Database(DB_PATH);
  
  try {
    const stmt = db.prepare(`
      SELECT 1 FROM GRANTS
      WHERE username = ? AND resource_name = ? AND permission_level = 3
      LIMIT 1
    `);
    const result = stmt.get(username, resourcename);
    return result !== undefined;
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
    add_user,
    delete_user,
    set_grant,
    remove_grant,
    user_is_resource_admin,
    PERMISSIONS
};
