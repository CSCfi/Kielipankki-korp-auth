#!/usr/bin/env python3
"""
korp-auth admin tool

Command-line tool for managing entitlements and grants in korp-auth.
Supports importing from TSV files and command-line options, makes
admin API operations (not database writes).
"""

import argparse
import sys
import os
import requests
from typing import List, Tuple, Optional
from collections import defaultdict


class KorpAuthClient:
    """Client for interacting with korp-auth admin API"""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    def list_entitlements(self) -> List[dict]:
        """List all entitlements"""
        response = requests.get(
            f"{self.base_url}/admin/entitlements", headers=self.headers
        )
        response.raise_for_status()
        return response.json()["entitlements"]

    def get_entitlement(self, urn: str) -> dict:
        """Get single entitlement with grants"""
        response = requests.get(
            f'{self.base_url}/admin/entitlement/{requests.utils.quote(urn, safe="")}',
            headers=self.headers,
        )
        response.raise_for_status()
        return response.json()

    def create_entitlement(
        self, urn: str, description: str, grants: Optional[List[dict]] = None
    ) -> dict:
        """Create or update entitlement with optional grants"""
        data = {"urn": urn, "description": description}
        if grants:
            data["grants"] = grants

        response = requests.post(
            f"{self.base_url}/admin/entitlement", headers=self.headers, json=data
        )
        response.raise_for_status()
        return response.json()

    def delete_entitlement(self, urn: str):
        """Delete entitlement and all its grants"""
        response = requests.delete(
            f'{self.base_url}/admin/entitlement/{requests.utils.quote(urn, safe="")}',
            headers=self.headers,
        )
        response.raise_for_status()

    def add_grant(self, entitlement_urn: str, resource_name: str, level: int) -> dict:
        """Add or update single grant"""
        data = {
            "entitlementUrn": entitlement_urn,
            "resourceName": resource_name,
            "level": level,
        }
        response = requests.post(
            f"{self.base_url}/admin/grant", headers=self.headers, json=data
        )
        response.raise_for_status()
        return response.json()

    def delete_grant(self, entitlement_urn: str, resource_name: str):
        """Delete single grant"""
        params = {"entitlementUrn": entitlement_urn, "resourceName": resource_name}
        response = requests.delete(
            f"{self.base_url}/admin/grant", headers=self.headers, params=params
        )
        response.raise_for_status()


def parse_tsv_line(line: str) -> Optional[Tuple[str, str, str]]:
    """
    Parse a TSV line in format: URN<TAB>RESOURCE_NAME[<TAB>DESCRIPTION]

    Returns: (urn, resource_name, description) or None if line should be skipped
    Description is empty string if not provided (third column optional)
    """
    line = line.strip()

    # Skip empty lines and comments
    if not line or line.startswith("#"):
        return None

    # Split by tab
    parts = line.split("\t")
    if len(parts) < 2 or len(parts) > 3:
        print(
            f"Warning: Skipping malformed line (expected 2-3 tab-separated fields): {line}",
            file=sys.stderr,
        )
        return None

    urn = parts[0].strip()
    resource_name = parts[1].strip()
    description = parts[2].strip() if len(parts) >= 3 else ""

    if not urn or not resource_name:
        print(
            f"Warning: Skipping line with empty URN or resource name: {line}",
            file=sys.stderr,
        )
        return None

    return (urn, resource_name, description)


def read_tsv_file(filepath: str) -> dict:
    """
    Read TSV file and group grants by entitlement URN

    Returns: dict mapping URN -> (resource_list, description)
    If same URN appears multiple times, keeps first non-empty description
    """
    grants_by_urn = defaultdict(lambda: ([], ""))

    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            result = parse_tsv_line(line)
            if result:
                urn, resource_name, description = result
                resources, existing_desc = grants_by_urn[urn]
                resources.append(resource_name)
                # Keep first non-empty description
                if description and not existing_desc:
                    grants_by_urn[urn] = (resources, description)
                else:
                    grants_by_urn[urn] = (resources, existing_desc)

    return dict(grants_by_urn)


def cmd_import(args, client: KorpAuthClient):
    """Import entitlements and grants from TSV file"""
    print(f"Reading from: {args.file}")

    try:
        grants_by_urn = read_tsv_file(args.file)
    except FileNotFoundError:
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    print(f"Found {len(grants_by_urn)} unique entitlements")

    # Default permission level
    level = args.level

    success_count = 0
    error_count = 0

    for urn, (resources, tsv_description) in grants_by_urn.items():
        print(f"\nProcessing: {urn} ({len(resources)} grants)")

        # Use TSV description if provided, otherwise fall back to --description argument, otherwise empty
        description = tsv_description or args.description or ""

        # Prepare grants
        grants = [{"resourceName": res, "level": level} for res in resources]

        try:
            result = client.create_entitlement(urn, description, grants)
            status = "Created" if result["created"] else "Updated"
            print(f"  ✓ {status} entitlement with {result['grantsAdded']} grants")
            success_count += 1
        except requests.exceptions.HTTPError as e:
            print(
                f"  ✗ Error: {e.response.status_code} - {e.response.text}",
                file=sys.stderr,
            )
            error_count += 1
            if not args.continue_on_error:
                return 1
        except Exception as e:
            print(f"  ✗ Error: {e}", file=sys.stderr)
            error_count += 1
            if not args.continue_on_error:
                return 1

    print(f"\n{'='*60}")
    print(f"Summary: {success_count} succeeded, {error_count} failed")
    print(f"{'='*60}")

    return 0 if error_count == 0 else 1


def cmd_list(args, client: KorpAuthClient):
    """List entitlements"""
    try:
        entitlements = client.list_entitlements()
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not entitlements:
        print("No entitlements found")
        return 0

    print(f"Found {len(entitlements)} entitlements:\n")

    for ent in entitlements:
        print(f"URN: {ent['urn']}")
        print(f"  Description: {ent['description']}")
        print(f"  Grants: {ent['grant_count']}")
        print(f"  Created: {ent['created_at']}")

        if args.verbose:
            # Fetch full details including grants
            try:
                details = client.get_entitlement(ent["urn"])
                if details["grants"]:
                    print(f"  Resources:")
                    for grant in details["grants"]:
                        level_name = {1: "READ", 2: "WRITE", 3: "ADMIN"}.get(
                            grant["permission_level"], "?"
                        )
                        print(f"    - {grant['resource_name']} ({level_name})")
            except Exception as e:
                print(f"    (Could not fetch grant details: {e})", file=sys.stderr)

        print()

    return 0


def cmd_export(args, client: KorpAuthClient):
    """Export entitlements to TSV format"""
    try:
        entitlements = client.list_entitlements()
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    lines = []

    for ent in entitlements:
        # Fetch full details to get grants
        try:
            details = client.get_entitlement(ent["urn"])
            for grant in details["grants"]:
                lines.append(f"{ent['urn']}\t{grant['resource_name']}")
        except Exception as e:
            print(
                f"Warning: Could not fetch grants for {ent['urn']}: {e}",
                file=sys.stderr,
            )

    output = "\n".join(lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
            f.write("\n")
        print(f"Exported {len(lines)} grants to: {args.output}")
    else:
        print(output)

    return 0


def cmd_add_entitlement(args, client: KorpAuthClient):
    """Add or update single entitlement"""
    try:
        result = client.create_entitlement(args.urn, args.description)
        status = "Created" if result["created"] else "Updated"
        print(f"✓ {status} entitlement: {result['urn']}")
        return 0
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_add_grant(args, client: KorpAuthClient):
    """Add or update single grant"""
    try:
        result = client.add_grant(args.urn, args.resource, args.level)
        print(
            f"✓ Added grant: {result['entitlementUrn']} -> {result['resourceName']} (level {result['level']})"
        )
        return 0
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_delete_entitlement(args, client: KorpAuthClient):
    """Delete entitlement"""
    if not args.force:
        confirm = input(f"Delete entitlement '{args.urn}' and all its grants? [y/N]: ")
        if confirm.lower() != "y":
            print("Cancelled")
            return 0

    try:
        client.delete_entitlement(args.urn)
        print(f"✓ Deleted entitlement: {args.urn}")
        return 0
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_delete_grant(args, client: KorpAuthClient):
    """Delete single grant"""
    try:
        client.delete_grant(args.urn, args.resource)
        print(f"✓ Deleted grant: {args.urn} -> {args.resource}")
        return 0
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="Korp Auth Admin Tool - Manage entitlements and grants",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import from TSV file
  %(prog)s import entitlements.tsv

  # List all entitlements
  %(prog)s list

  # List with full grant details
  %(prog)s list -v

  # Export to TSV
  %(prog)s export -o output.tsv

  # Add single entitlement
  %(prog)s add-entitlement "urn:nbn:fi:lb-123@LBR" "Test Entitlement"

  # Add single grant
  %(prog)s add-grant "urn:nbn:fi:lb-123@LBR" corpus-name --level 1

Environment variables:
  KORP_AUTH_URL      Base URL for korp-auth service (default: http://localhost)
  KORP_AUTH_API_KEY  Admin API key (used if --api-key-file not provided)

API Key Priority:
  1. --api-key-file (if specified)
  2. KORP_AUTH_API_KEY environment variable
  3. Prompt from stdin (if neither of the above is set)
        """,
    )

    # Global options
    parser.add_argument(
        "--url",
        default=os.getenv("KORP_AUTH_URL", "http://localhost"),
        help="Base URL for korp-auth service",
    )
    parser.add_argument("--api-key-file", help="Path to file containing admin API key")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Import command
    import_parser = subparsers.add_parser("import", help="Import from TSV file")
    import_parser.add_argument(
        "file", help="TSV file to import (format: URN<TAB>RESOURCE_NAME)"
    )
    import_parser.add_argument(
        "--level",
        type=int,
        default=1,
        choices=[1, 2, 3],
        help="Permission level (1=READ, 2=WRITE, 3=ADMIN, default: 1)",
    )
    import_parser.add_argument(
        "--description", help="Description for entitlements (default: auto-generated)"
    )
    import_parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue processing even if some entitlements fail",
    )

    # List command
    list_parser = subparsers.add_parser("list", help="List entitlements")
    list_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show full grant details for each entitlement",
    )

    # Export command
    export_parser = subparsers.add_parser("export", help="Export to TSV format")
    export_parser.add_argument("-o", "--output", help="Output file (default: stdout)")

    # Add entitlement command
    add_ent_parser = subparsers.add_parser(
        "add-entitlement", help="Add or update entitlement"
    )
    add_ent_parser.add_argument("urn", help="Entitlement URN")
    add_ent_parser.add_argument("description", help="Description")

    # Add grant command
    add_grant_parser = subparsers.add_parser("add-grant", help="Add or update grant")
    add_grant_parser.add_argument("urn", help="Entitlement URN")
    add_grant_parser.add_argument("resource", help="Resource name")
    add_grant_parser.add_argument(
        "--level",
        type=int,
        default=1,
        choices=[1, 2, 3],
        help="Permission level (1=READ, 2=WRITE, 3=ADMIN, default: 1)",
    )

    # Delete entitlement command
    del_ent_parser = subparsers.add_parser(
        "delete-entitlement", help="Delete entitlement"
    )
    del_ent_parser.add_argument("urn", help="Entitlement URN")
    del_ent_parser.add_argument(
        "-f", "--force", action="store_true", help="Skip confirmation prompt"
    )

    # Delete grant command
    del_grant_parser = subparsers.add_parser("delete-grant", help="Delete grant")
    del_grant_parser.add_argument("urn", help="Entitlement URN")
    del_grant_parser.add_argument("resource", help="Resource name")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Get API key with priority: 1) --api-key-file, 2) env var, 3) stdin
    api_key = None

    # 1. Try API key file (explicit argument takes precedence)
    if args.api_key_file:
        try:
            with open(args.api_key_file, "r") as f:
                api_key = f.read().strip()
        except FileNotFoundError:
            print(
                f"Error: API key file not found: {args.api_key_file}", file=sys.stderr
            )
            return 1
        except Exception as e:
            print(f"Error reading API key file: {e}", file=sys.stderr)
            return 1

    # 2. Try environment variable
    elif os.getenv("KORP_AUTH_API_KEY"):
        api_key = os.getenv("KORP_AUTH_API_KEY")

    # 3. Prompt user to enter from stdin
    else:
        print("Enter admin API key: ", file=sys.stderr, end="", flush=True)
        api_key = input().strip()

    # Validate API key
    if not api_key:
        print("Error: API key cannot be empty", file=sys.stderr)
        return 1

    # Create client
    client = KorpAuthClient(args.url, api_key)

    # Dispatch to command handler
    commands = {
        "import": cmd_import,
        "list": cmd_list,
        "export": cmd_export,
        "add-entitlement": cmd_add_entitlement,
        "add-grant": cmd_add_grant,
        "delete-entitlement": cmd_delete_entitlement,
        "delete-grant": cmd_delete_grant,
    }

    return commands[args.command](args, client)


if __name__ == "__main__":
    sys.exit(main())
