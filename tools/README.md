# Korp Auth Admin Tools

This directory contains administrative tools for managing entitlements and grants in korp-auth.

## korp-auth-admin.py

Python CLI tool for managing entitlements and grants via the admin API.

### Requirements

- `requests`
- The admin API key

### Configuration

**API Key Priority:**

The tool accepts the admin API key in three ways (in order of precedence):

1. **From a file**:
   ```bash
   pass lb_passwords Kielipankki-proxy/korp-auth-api-key > korp-auth-key
   ./korp-auth-admin.py --api-key-file korp-auth-key <command>
   ```

2. **From environment variable**:
   ```bash
   export KORP_AUTH_API_KEY="your-admin-api-key"
   ./korp-auth-admin.py <command>
   ```

3. **From stdin** (if neither file nor env var is set):
   ```bash
   ./korp-auth-admin.py list
   # Prompts: Enter admin API key
   ```

**Server URL:**

```bash
export KORP_AUTH_URL="https://kielipankki.fi/api/auth"  # or use --url flag
```

### Commands

#### Import from TSV file

Import entitlements and grants from a tab-separated file in legacy format:

```bash
./korp-auth-admin.py import entitlements.tsv
```

**TSV Format:**
```
urn:nbn:fi:lb-201403261@LBR	DMA
urn:nbn:fi:lb-201403261@LBR	DMA_20160421	Special date version for some reason
urn:nbn:fi:lb-2014032621@LBR	FSTC_FISC_LIT	This is totally lit
```

Format: `URN<TAB>RESOURCE_NAME[<TAB>DESCRIPTION]`

The description column is optional. If provided in the TSV file, it will be used for that entitlement. If not provided, the `--description` argument will be used as fallback. If neither is provided, the description will be empty.

**Options:**
- `--level N` - Permission level for all grants (1=READ, 2=WRITE, 3=ADMIN, default: 1)
- `--description "text"` - Fallback description for entitlements without description in TSV (default: empty)
- `--continue-on-error` - Don't stop if some entitlements fail

**Examples:**
```bash
# Import with READ permission (default)
./korp-auth-admin.py import legacy_dump.tsv

# Import with WRITE permission
./korp-auth-admin.py import legacy_dump.tsv --level 2

# Import with fallback description (used for entries without TSV description)
./korp-auth-admin.py import legacy_dump.tsv --description "Migrated from legacy system 2025-01"

# Import with 3-column TSV (descriptions in file take precedence over --description)
./korp-auth-admin.py import entitlements_with_descriptions.tsv

# Continue processing even if some fail
./korp-auth-admin.py import legacy_dump.tsv --continue-on-error
```

#### List entitlements

```bash
# Basic list (shows grant counts)
./korp-auth-admin.py list

# Verbose list (shows all grants)
./korp-auth-admin.py list -v
```

#### Export to TSV

```bash
# Export to stdout
./korp-auth-admin.py export

# Export to file
./korp-auth-admin.py export -o entitlements.tsv
```

#### Add single entitlement

```bash
./korp-auth-admin.py add-entitlement "urn:nbn:fi:lb-123@LBR" "Test Entitlement"
```

#### Add single grant

```bash
# Add READ grant (level 1)
./korp-auth-admin.py add-grant "urn:nbn:fi:lb-123@LBR" corpus-name

# Add WRITE grant (level 2)
./korp-auth-admin.py add-grant "urn:nbn:fi:lb-123@LBR" corpus-name --level 2

# Add ADMIN grant (level 3)
./korp-auth-admin.py add-grant "urn:nbn:fi:lb-123@LBR" corpus-name --level 3
```

#### Delete entitlement

```bash
# With confirmation prompt
./korp-auth-admin.py delete-entitlement "urn:nbn:fi:lb-123@LBR"

# Skip confirmation
./korp-auth-admin.py delete-entitlement "urn:nbn:fi:lb-123@LBR" --force
```

#### Delete grant

```bash
./korp-auth-admin.py delete-grant "urn:nbn:fi:lb-123@LBR" corpus-name
```

### Migration Workflow

**From legacy MariaDB system:**

1. Export from `korp-authdb.py lbr_map` to TSV

2. Import TSV korp-auth:
   ```bash
   ./korp-auth-admin.py --api-key-file ~/korp-auth-key import korp_authdb_dump.tsv --level 1 --description "Migrated from korp-authdb"
   ```

3. Verify:
   ```bash
   ./korp-auth-admin.py --api-key-file ~/korp-auth-key list -v | head -20
   ```

### Error Handling

The tool provides clear error messages:

- **401 Unauthorized**: Check your API key
- **404 Not Found**: Entitlement or resource doesn't exist
- **400 Bad Request**: Validation error (check your input)
- **500 Internal Server Error**: Server-side issue (check server logs)

Use `--continue-on-error` with `import` to skip failed entries and continue processing.

### TSV File Format Details

**Supported:**
- Tab-separated values (URN, resource name, optional description)
- Empty lines (ignored)
- Comments starting with `#` (ignored)
- Multiple grants for same URN (will be grouped)
- Multiple URNs for same resource (each creates separate grant)
- Mixed 2-column and 3-column format (description column optional per-line)

### Debugging

Enable verbose output by running with DEBUG:

```bash
# For the tool itself
python3 -u korp-auth-admin.py list -v

# For the API server (if you control it)
DEBUG=korp-auth:admin npm start
```
