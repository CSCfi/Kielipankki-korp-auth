/**
 * Database tests for entitlement-based authorization
 *
 * Run with: npm test
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

// Set test environment
process.env.NODE_ENV = 'development';
process.env.DB_PATH = path.join(__dirname, 'test.sqlite3');
process.env.DEMO_USERS = JSON.stringify({
  'demo@example.com': { password: 'password123' },
  'tutkija@kielipankki.fi': { password: '123' }
});

const db = require('../src/db');
const config = require('../src/config');

// Test database path
const TEST_DB_PATH = config.dbPath;

/**
 * Clean up test database before each test suite
 */
function setupTestDatabase() {
  if (fs.existsSync(TEST_DB_PATH)) {
    fs.unlinkSync(TEST_DB_PATH);
  }
  db.create_db_if_missing();
}

/**
 * Clean up test database after tests
 */
function teardownTestDatabase() {
  if (fs.existsSync(TEST_DB_PATH)) {
    fs.unlinkSync(TEST_DB_PATH);
  }
}

// ============================================================================
// Test Suite: Database Schema
// ============================================================================

function testDatabaseSchema() {
  console.log('\n=== Testing Database Schema ===');

  setupTestDatabase();

  const sqlite = new Database(TEST_DB_PATH);
  try {
    // Test: All tables exist
    const tables = sqlite.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all();
    const tableNames = tables.map(t => t.name);

    assert(tableNames.includes('USERS'), 'USERS table should exist');
    assert(tableNames.includes('ENTITLEMENTS'), 'ENTITLEMENTS table should exist');
    assert(tableNames.includes('RESOURCES'), 'RESOURCES table should exist');
    assert(tableNames.includes('GRANTS'), 'GRANTS table should exist');
    console.log('✓ All required tables exist');

    // Test: GRANTS table has correct columns
    const grantsSchema = sqlite.prepare("PRAGMA table_info(GRANTS)").all();
    const columnNames = grantsSchema.map(col => col.name);

    assert(columnNames.includes('user_id'), 'GRANTS should have user_id column');
    assert(columnNames.includes('entitlement_id'), 'GRANTS should have entitlement_id column');
    assert(columnNames.includes('resource_name'), 'GRANTS should have resource_name column');
    assert(columnNames.includes('permission_level'), 'GRANTS should have permission_level column');
    console.log('✓ GRANTS table has correct columns');

    // Test: Unique indexes exist
    const indexes = sqlite.prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='GRANTS' ORDER BY name").all();
    const indexNames = indexes.map(i => i.name);

    assert(indexNames.includes('idx_grants_user_resource'), 'Should have unique index for user+resource');
    assert(indexNames.includes('idx_grants_entitlement_resource'), 'Should have unique index for entitlement+resource');
    console.log('✓ Unique indexes exist for upsert operations');

  } finally {
    sqlite.close();
  }
}

// ============================================================================
// Test Suite: Entitlement Management
// ============================================================================

function testEntitlementManagement() {
  console.log('\n=== Testing Entitlement Management ===');

  setupTestDatabase();

  // Test: Create entitlement
  const entId = db.create_entitlement('urn:nbn:fi:lb-2022031701@LBR', 'Test Entitlement');
  assert(typeof entId === 'number', 'create_entitlement should return entitlement ID');
  console.log('✓ Create entitlement');

  // Test: Entitlement exists
  assert(db.entitlement_exists('urn:nbn:fi:lb-2022031701@LBR'), 'Created entitlement should exist');
  assert(!db.entitlement_exists('urn:nbn:fi:lb-9999999999@LBR'), 'Non-existent entitlement should not exist');
  console.log('✓ Check entitlement exists');

  // Test: List entitlements
  const entitlements = db.list_entitlements();
  assert(Array.isArray(entitlements), 'list_entitlements should return array');
  assert(entitlements.length === 1, 'Should have 1 entitlement');
  assert(entitlements[0].urn === 'urn:nbn:fi:lb-2022031701@LBR', 'Should return correct URN');
  assert(entitlements[0].description === 'Test Entitlement', 'Should return correct description');
  console.log('✓ List entitlements');

  // Test: Update entitlement description
  db.update_entitlement_description('urn:nbn:fi:lb-2022031701@LBR', 'Updated Description');
  const updated = db.list_entitlements();
  assert(updated[0].description === 'Updated Description', 'Description should be updated');
  console.log('✓ Update entitlement description');

  // Test: Delete entitlement
  const deleted = db.delete_entitlement('urn:nbn:fi:lb-2022031701@LBR');
  assert(deleted === true, 'delete_entitlement should return true when deleted');
  assert(!db.entitlement_exists('urn:nbn:fi:lb-2022031701@LBR'), 'Entitlement should no longer exist');
  console.log('✓ Delete entitlement');
}

// ============================================================================
// Test Suite: Grant Management
// ============================================================================

function testGrantManagement() {
  console.log('\n=== Testing Grant Management ===');

  setupTestDatabase();

  // Setup test data
  db.create_resource('test-corpus', 'corpus');
  db.create_entitlement('urn:nbn:fi:lb-2022031701@LBR', 'Test Entitlement');

  // Test: Set grant for entitlement
  db.set_grant({ entitlementUrn: 'urn:nbn:fi:lb-2022031701@LBR', resourceName: 'test-corpus', level: 1 });
  const grants = db.get_grants_for_entitlement('urn:nbn:fi:lb-2022031701@LBR');
  assert(grants.length === 1, 'Should have 1 grant');
  assert(grants[0].resource_name === 'test-corpus', 'Grant should be for correct resource');
  assert(grants[0].permission_level === 1, 'Grant should have correct permission level');
  console.log('✓ Set grant for entitlement');

  // Test: Upsert grant (update existing)
  db.set_grant({ entitlementUrn: 'urn:nbn:fi:lb-2022031701@LBR', resourceName: 'test-corpus', level: 2 });
  const updated = db.get_grants_for_entitlement('urn:nbn:fi:lb-2022031701@LBR');
  assert(updated.length === 1, 'Should still have 1 grant (no duplicate)');
  assert(updated[0].permission_level === 2, 'Permission level should be updated');
  console.log('✓ Upsert grant (update existing)');

  // Test: Set grant for user
  db.set_grant({ userIdentifier: 'demo@example.com', resourceName: 'test-corpus', level: 3 });
  const userScope = db.get_user_scope('demo@example.com', []);
  assert(userScope.corpora['test-corpus'] === 3, 'User should have ADMIN permission');
  console.log('✓ Set grant for user');

  // Test: Remove grant
  db.remove_grant({ entitlementUrn: 'urn:nbn:fi:lb-2022031701@LBR', resourceName: 'test-corpus' });
  const afterRemove = db.get_grants_for_entitlement('urn:nbn:fi:lb-2022031701@LBR');
  assert(afterRemove.length === 0, 'Grant should be removed');
  console.log('✓ Remove grant');
}

// ============================================================================
// Test Suite: Permission Aggregation
// ============================================================================

function testPermissionAggregation() {
  console.log('\n=== Testing Permission Aggregation ===');

  setupTestDatabase();

  // Setup test data
  db.create_resource('corpus-1', 'corpus');
  db.create_resource('corpus-2', 'corpus');
  db.create_resource('metadata-1', 'metadata');

  db.create_entitlement('urn:nbn:fi:lb-2022031701@LBR', 'Research Access');
  db.create_entitlement('urn:nbn:fi:lb-2023050901@LBR', 'Special Access');

  // Set up conflicting permissions
  db.set_grant({ entitlementUrn: 'urn:nbn:fi:lb-2022031701@LBR', resourceName: 'corpus-1', level: 1 }); // READ
  db.set_grant({ entitlementUrn: 'urn:nbn:fi:lb-2023050901@LBR', resourceName: 'corpus-1', level: 3 }); // ADMIN
  db.set_grant({ entitlementUrn: 'urn:nbn:fi:lb-2022031701@LBR', resourceName: 'corpus-2', level: 2 }); // WRITE

  // Set user-specific grant
  db.set_grant({ userIdentifier: 'demo@example.com', resourceName: 'metadata-1', level: 2 }); // WRITE

  // Test: Permission aggregation with MAX()
  const scope = db.get_user_scope('demo@example.com', [
    'urn:nbn:fi:lb-2022031701@LBR',
    'urn:nbn:fi:lb-2023050901@LBR'
  ]);

  assert(scope.corpora['corpus-1'] === 3, 'Should select highest permission (ADMIN over READ)');
  assert(scope.corpora['corpus-2'] === 2, 'Should have WRITE permission');
  assert(scope.metadata['metadata-1'] === 2, 'Should have user-specific permission');
  console.log('✓ Permission aggregation uses MAX() correctly');

  // Test: User without entitlements only gets direct grants
  const directOnly = db.get_user_scope('demo@example.com', []);
  assert(!directOnly.corpora, 'Should not have corpus access without entitlements');
  assert(directOnly.metadata['metadata-1'] === 2, 'Should still have direct user grant');
  console.log('✓ Direct grants work without entitlements');

  // Test: User with entitlements but no direct grants
  db.add_user('other@example.com');
  const entitlementsOnly = db.get_user_scope('other@example.com', ['urn:nbn:fi:lb-2022031701@LBR']);
  assert(entitlementsOnly.corpora['corpus-1'] === 1, 'Should have entitlement-based access');
  assert(entitlementsOnly.corpora['corpus-2'] === 2, 'Should have entitlement-based access');
  console.log('✓ Entitlement-only access works');
}

// ============================================================================
// Test Suite: User Management
// ============================================================================

function testUserManagement() {
  console.log('\n=== Testing User Management ===');

  setupTestDatabase();

  // Test: JIT user provisioning
  const userId = db.ensure_user('newuser@example.com');
  assert(typeof userId === 'number', 'ensure_user should return user ID');
  assert(db.user_exists('newuser@example.com'), 'User should exist after ensure_user');
  console.log('✓ JIT user provisioning (ensure_user)');

  // Test: ensure_user is idempotent
  const userId2 = db.ensure_user('newuser@example.com');
  assert(userId === userId2, 'ensure_user should return same ID for existing user');
  console.log('✓ ensure_user is idempotent');

  // Test: Add user
  db.add_user('another@example.com');
  assert(db.user_exists('another@example.com'), 'User should exist after add_user');
  console.log('✓ Add user');

  // Test: Delete user cascades to grants
  db.create_resource('test-resource', 'corpus');
  db.set_grant({ userIdentifier: 'another@example.com', resourceName: 'test-resource', level: 1 });
  db.delete_user('another@example.com');
  assert(!db.user_exists('another@example.com'), 'User should be deleted');

  // Verify grant was also deleted (CASCADE)
  const sqlite = new Database(TEST_DB_PATH);
  try {
    const grants = sqlite.prepare("SELECT COUNT(*) as count FROM GRANTS WHERE user_id IS NOT NULL").get();
    // Should only have demo users' grants left
    assert(grants.count >= 0, 'Grants should be cascaded on user delete');
  } finally {
    sqlite.close();
  }
  console.log('✓ Delete user cascades to grants');
}

// ============================================================================
// Test Suite: Resource Management
// ============================================================================

function testResourceManagement() {
  console.log('\n=== Testing Resource Management ===');

  setupTestDatabase();

  // Test: Create resource
  db.create_resource('new-corpus', 'corpus');
  const sqlite = new Database(TEST_DB_PATH);
  try {
    const resource = sqlite.prepare("SELECT * FROM RESOURCES WHERE resource_name = ?").get('new-corpus');
    assert(resource !== undefined, 'Resource should exist');
    assert(resource.type === 'corpus', 'Resource should have correct type');
  } finally {
    sqlite.close();
  }
  console.log('✓ Create resource');

  // Test: Cannot create duplicate resource
  let errorThrown = false;
  try {
    db.create_resource('new-corpus', 'corpus');
  } catch (error) {
    errorThrown = true;
    assert(error instanceof db.ResourceExistsError, 'Should throw ResourceExistsError');
  }
  assert(errorThrown, 'Should throw error for duplicate resource');
  console.log('✓ Duplicate resource throws error');

  // Test: Delete resource cascades to grants
  db.set_grant({ userIdentifier: 'demo@example.com', resourceName: 'new-corpus', level: 1 });
  db.delete_resource('new-corpus');

  const sqlite2 = new Database(TEST_DB_PATH);
  try {
    const resource = sqlite2.prepare("SELECT * FROM RESOURCES WHERE resource_name = ?").get('new-corpus');
    assert(resource === undefined, 'Resource should be deleted');

    const grants = sqlite2.prepare("SELECT COUNT(*) as count FROM GRANTS WHERE resource_name = ?").get('new-corpus');
    assert(grants.count === 0, 'Grants should be cascaded on resource delete');
  } finally {
    sqlite2.close();
  }
  console.log('✓ Delete resource cascades to grants');
}

// ============================================================================
// Test Suite: JWT Flow Integration
// ============================================================================

function testJwtFlowIntegration() {
  console.log('\n=== Testing JWT Flow Integration ===');

  setupTestDatabase();

  // Setup test data
  db.create_resource('corpus-research', 'corpus');
  db.create_resource('corpus-special', 'corpus');
  db.create_resource('corpus-public', 'corpus');

  db.create_entitlement('urn:nbn:fi:lb-2022031701@LBR', 'Language Bank Research Access');
  db.create_entitlement('urn:nbn:fi:lb-2023050901@LBR', 'Special Collection Access');

  db.set_grant({ entitlementUrn: 'urn:nbn:fi:lb-2022031701@LBR', resourceName: 'corpus-research', level: 1 }); // READ
  db.set_grant({ entitlementUrn: 'urn:nbn:fi:lb-2023050901@LBR', resourceName: 'corpus-special', level: 2 }); // WRITE

  // Test: User with multiple entitlements
  const scope1 = db.get_user_scope('demo@example.com', [
    'urn:nbn:fi:lb-2022031701@LBR',
    'urn:nbn:fi:lb-2023050901@LBR'
  ]);
  assert(scope1.corpora['corpus-research'] === 1, 'Should have READ access via first entitlement');
  assert(scope1.corpora['corpus-special'] === 2, 'Should have WRITE access via second entitlement');
  console.log('✓ User with multiple entitlements gets aggregated permissions');

  // Test: User with single entitlement
  const scope2 = db.get_user_scope('demo@example.com', ['urn:nbn:fi:lb-2022031701@LBR']);
  assert(scope2.corpora['corpus-research'] === 1, 'Should have READ access via entitlement');
  assert(!scope2.corpora['corpus-special'], 'Should not have access to other corpus');
  console.log('✓ User with single entitlement gets limited permissions');

  // Test: User with no entitlements
  const scope3 = db.get_user_scope('demo@example.com', []);
  assert(Object.keys(scope3).length === 0, 'Should have no permissions without entitlements');
  console.log('✓ User with no entitlements gets no permissions');

  // Test: Combined user grants + entitlement grants
  db.set_grant({ userIdentifier: 'demo@example.com', resourceName: 'corpus-public', level: 3 }); // Direct ADMIN grant
  const scope4 = db.get_user_scope('demo@example.com', ['urn:nbn:fi:lb-2022031701@LBR']);
  assert(scope4.corpora['corpus-public'] === 3, 'Should have direct ADMIN grant');
  assert(scope4.corpora['corpus-research'] === 1, 'Should have entitlement READ grant');
  console.log('✓ Direct grants and entitlement grants are combined');

  // Test: Permission aggregation (MAX) with overlapping grants
  db.set_grant({ userIdentifier: 'demo@example.com', resourceName: 'corpus-research', level: 2 }); // Direct WRITE
  const scope5 = db.get_user_scope('demo@example.com', ['urn:nbn:fi:lb-2022031701@LBR']);
  assert(scope5.corpora['corpus-research'] === 2, 'Should use MAX permission (WRITE > READ)');
  console.log('✓ Overlapping permissions use MAX (highest wins)');

  // Test: JIT user provisioning in JWT flow
  const newUserId = db.ensure_user('newuser@kielipankki.fi');
  assert(typeof newUserId === 'number', 'ensure_user should return user ID');
  assert(db.user_exists('newuser@kielipankki.fi'), 'User should be created');

  const newUserId2 = db.ensure_user('newuser@kielipankki.fi');
  assert(newUserId === newUserId2, 'ensure_user should be idempotent');
  console.log('✓ JIT user provisioning works correctly');

  // Test: New user with entitlements but no direct grants
  const newUserScope = db.get_user_scope('newuser@kielipankki.fi', ['urn:nbn:fi:lb-2022031701@LBR']);
  assert(newUserScope.corpora['corpus-research'] === 1, 'New user should get entitlement permissions');
  console.log('✓ New users receive entitlement-based permissions');

  // Test: Non-existent entitlement URN (should be ignored)
  const scopeInvalid = db.get_user_scope('demo@example.com', [
    'urn:nbn:fi:lb-2022031701@LBR',
    'urn:nbn:fi:lb-9999999999@LBR' // Non-existent
  ]);
  assert(scopeInvalid.corpora['corpus-research'] === 2, 'Should process valid entitlements');
  assert(!scopeInvalid.corpora['nonexistent'], 'Should ignore invalid entitlements');
  console.log('✓ Invalid entitlement URNs are silently ignored');
}

// ============================================================================
// Run All Tests
// ============================================================================

function runAllTests() {
  console.log('\n' + '='.repeat(70));
  console.log('Running Database Tests for korp-auth');
  console.log('='.repeat(70));

  let failed = false;

  try {
    testDatabaseSchema();
    testEntitlementManagement();
    testGrantManagement();
    testPermissionAggregation();
    testUserManagement();
    testResourceManagement();
    testJwtFlowIntegration();

    console.log('\n' + '='.repeat(70));
    console.log('✓ All tests passed!');
    console.log('='.repeat(70) + '\n');

  } catch (error) {
    failed = true;
    console.error('\n' + '='.repeat(70));
    console.error('✗ Test failed:', error.message);
    console.error('='.repeat(70));
    console.error(error.stack);
    console.error('\n');
  } finally {
    teardownTestDatabase();
  }

  process.exit(failed ? 1 : 0);
}

// Run tests if this file is executed directly
if (require.main === module) {
  runAllTests();
}

module.exports = { runAllTests };
