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

    def get_entitlement(self, identifier: str) -> dict:
        """Get single entitlement with grants"""
        response = requests.get(
            f'{self.base_url}/admin/entitlement/{requests.utils.quote(identifier, safe="")}',
            headers=self.headers,
        )
        response.raise_for_status()
        return response.json()

    def create_entitlement(
        self, identifier: str, description: str, grants: Optional[List[dict]] = None
    ) -> dict:
        """Create or update entitlement with optional grants"""
        data = {"identifier": identifier, "description": description}
        if grants:
            data["grants"] = grants

        response = requests.post(
            f"{self.base_url}/admin/entitlement", headers=self.headers, json=data
        )
        response.raise_for_status()
        return response.json()

    def delete_entitlement(self, identifier: str):
        """Delete entitlement and all its grants"""
        response = requests.delete(
            f'{self.base_url}/admin/entitlement/{requests.utils.quote(identifier, safe="")}',
            headers=self.headers,
        )
        response.raise_for_status()

    def add_grant(self, entitlement_identifier: str, resource_name: str, level: int) -> dict:
        """Add or update single grant"""
        data = {
            "entitlementIdentifier": entitlement_identifier,
            "resourceName": resource_name,
            "level": level,
        }
        response = requests.post(
            f"{self.base_url}/admin/grant", headers=self.headers, json=data
        )
        response.raise_for_status()
        return response.json()

    def delete_grant(self, entitlement_identifier: str, resource_name: str):
        """Delete single grant"""
        params = {"entitlementIdentifier": entitlement_identifier, "resourceName": resource_name}
        response = requests.delete(
            f"{self.base_url}/admin/grant", headers=self.headers, params=params
        )
        response.raise_for_status()

    def list_resources(self) -> List[dict]:
        """List all resources"""
        response = requests.get(
            f"{self.base_url}/admin/resources", headers=self.headers
        )
        response.raise_for_status()
        return response.json()["resources"]

    def create_resource(self, name: str, resource_type: str) -> dict:
        """Create a new resource"""
        data = {"name": name, "type": resource_type}
        response = requests.post(
            f"{self.base_url}/admin/resource", headers=self.headers, json=data
        )
        response.raise_for_status()
        return response.json()

    def delete_resource(self, name: str):
        """Delete a resource and all its grants"""
        response = requests.delete(
            f'{self.base_url}/admin/resource/{requests.utils.quote(name, safe="")}',
            headers=self.headers,
        )
        response.raise_for_status()


def parse_tsv_line(line: str) -> Optional[Tuple[str, str, str]]:
    """
    Parse a TSV line in format: IDENTIFIER<TAB>RESOURCE_NAME[<TAB>DESCRIPTION]

    Returns: (identifier, resource_name, description) or None if line should be skipped
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

    identifier = parts[0].strip()
    resource_name = parts[1].strip()
    description = parts[2].strip() if len(parts) >= 3 else ""

    if not identifier or not resource_name:
        print(
            f"Warning: Skipping line with empty identifier or resource name: {line}",
            file=sys.stderr,
        )
        return None

    return (identifier, resource_name, description)


def read_tsv_file(filepath: str) -> dict:
    """
    Read TSV file and group grants by entitlement identifier

    Returns: dict mapping identifier -> (resource_list, description)
    If same identifier appears multiple times, keeps first non-empty description
    """
    grants_by_identifier = defaultdict(lambda: ([], ""))

    with open(filepath, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            result = parse_tsv_line(line)
            if result:
                identifier, resource_name, description = result
                resources, existing_desc = grants_by_identifier[identifier]
                resources.append(resource_name)
                # Keep first non-empty description
                if description and not existing_desc:
                    grants_by_identifier[identifier] = (resources, description)
                else:
                    grants_by_identifier[identifier] = (resources, existing_desc)

    return dict(grants_by_identifier)


def cmd_import(args, client: KorpAuthClient):
    """Import entitlements and grants from TSV file"""
    print(f"Reading from: {args.file}")

    try:
        grants_by_identifier = read_tsv_file(args.file)
    except FileNotFoundError:
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    print(f"Found {len(grants_by_identifier)} unique entitlements")

    # Default permission level
    level = args.level

    success_count = 0
    error_count = 0

    for identifier, (resources, tsv_description) in grants_by_identifier.items():
        print(f"\nProcessing: {identifier} ({len(resources)} grants)")

        # Use TSV description if provided, otherwise fall back to --description argument, otherwise empty
        description = tsv_description or args.description or ""

        # Prepare grants
        grants = [{"resourceName": res, "level": level} for res in resources]

        try:
            result = client.create_entitlement(identifier, description, grants)
            status = "Created" if result["created"] else "Updated"
            print(f"  ✓ {status} entitlement with {result['grantsSet']} grants")
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
        print(f"Identifier: {ent['identifier']}")
        print(f"  Description: {ent['description']}")
        print(f"  Grants: {ent['grant_count']}")
        print(f"  Created: {ent['created_at']}")

        if args.verbose:
            # Fetch full details including grants
            try:
                details = client.get_entitlement(ent["identifier"])
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
            details = client.get_entitlement(ent["identifier"])
            for grant in details["grants"]:
                lines.append(f"{ent['identifier']}\t{grant['resource_name']}")
        except Exception as e:
            print(
                f"Warning: Could not fetch grants for {ent['identifier']}: {e}",
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
        result = client.create_entitlement(args.identifier, args.description)
        status = "Created" if result["created"] else "Updated"
        print(f"✓ {status} entitlement: {result['identifier']}")
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
        result = client.add_grant(args.identifier, args.resource, args.level)
        print(
            f"✓ Added grant: {result['entitlementIdentifier']} -> {result['resourceName']} (level {result['level']})"
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
        confirm = input(f"Delete entitlement '{args.identifier}' and all its grants? [y/N]: ")
        if confirm.lower() != "y":
            print("Cancelled")
            return 0

    try:
        client.delete_entitlement(args.identifier)
        print(f"✓ Deleted entitlement: {args.identifier}")
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
        client.delete_grant(args.identifier, args.resource)
        print(f"✓ Deleted grant: {args.identifier} -> {args.resource}")
        return 0
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_list_resources(args, client: KorpAuthClient):
    """List resources"""
    try:
        resources = client.list_resources()
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not resources:
        print("No resources found")
        return 0

    print(f"Found {len(resources)} resources:\n")

    for res in resources:
        print(f"Name: {res['resource_name']}")
        print(f"  Type: {res['type']}")
        print(f"  Grants: {res['grant_count']}")
        print()

    return 0


def cmd_add_resource(args, client: KorpAuthClient):
    """Add a new resource"""
    try:
        result = client.create_resource(args.name, args.type)
        print(f"✓ Created resource: {result['name']} (type: {result['type']})")
        return 0
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 409:
            print(f"Error: Resource '{args.name}' already exists", file=sys.stderr)
        else:
            print(
                f"Error: {e.response.status_code} - {e.response.text}", file=sys.stderr
            )
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_delete_resource(args, client: KorpAuthClient):
    """Delete resource"""
    if not args.force:
        confirm = input(
            f"Delete resource '{args.name}' and all its grants? [y/N]: "
        )
        if confirm.lower() != "y":
            print("Cancelled")
            return 0

    try:
        client.delete_resource(args.name)
        print(f"✓ Deleted resource: {args.name}")
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

  # Delete entitlement
  %(prog)s delete-entitlement "urn:nbn:fi:lb-123@LBR"

  # List all resources
  %(prog)s list-resources

  # Add a new resource (corpus by default)
  %(prog)s add-resource my-corpus

  # Add a metadata resource
  %(prog)s add-resource my-metadata --type metadata

  # Delete a resource
  %(prog)s delete-resource my-corpus

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
    add_ent_parser.add_argument("identifier", help="Entitlement identifier (e.g. URN)")
    add_ent_parser.add_argument("description", help="Description")

    # Add grant command
    add_grant_parser = subparsers.add_parser("add-grant", help="Add or update grant")
    add_grant_parser.add_argument("identifier", help="Entitlement identifier (e.g. URN)")
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
    del_ent_parser.add_argument("identifier", help="Entitlement identifier (e.g. URN)")
    del_ent_parser.add_argument(
        "-f", "--force", action="store_true", help="Skip confirmation prompt"
    )

    # Delete grant command
    del_grant_parser = subparsers.add_parser("delete-grant", help="Delete grant")
    del_grant_parser.add_argument("identifier", help="Entitlement identifier (e.g. URN)")
    del_grant_parser.add_argument("resource", help="Resource name")

    # List resources command
    subparsers.add_parser("list-resources", help="List all resources")

    # Add resource command
    add_res_parser = subparsers.add_parser("add-resource", help="Add a new resource")
    add_res_parser.add_argument("name", help="Resource name")
    add_res_parser.add_argument(
        "--type",
        default="corpus",
        choices=["corpus", "metadata", "other"],
        help="Resource type (default: corpus)",
    )

    # Delete resource command
    del_res_parser = subparsers.add_parser("delete-resource", help="Delete resource")
    del_res_parser.add_argument("name", help="Resource name")
    del_res_parser.add_argument(
        "-f", "--force", action="store_true", help="Skip confirmation prompt"
    )

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
        "list-resources": cmd_list_resources,
        "add-resource": cmd_add_resource,
        "delete-resource": cmd_delete_resource,
    }

    return commands[args.command](args, client)


if __name__ == "__main__":
    sys.exit(main())
