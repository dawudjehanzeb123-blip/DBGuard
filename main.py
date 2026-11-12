
import json
from pathlib import Path

data_file = Path(__file__).with_name("users.json")

try:
    with data_file.open("r", encoding="utf-8") as file:
        data = json.load(file)
except FileNotFoundError:
    print("ERROR: users.json was not found.")
    raise SystemExit(1)
except json.JSONDecodeError:
    print("ERROR: users.json contains invalid JSON.")
    raise SystemExit(1)

if not isinstance(data, dict):
    print("ERROR: The JSON's main content must be an object.")
    raise SystemExit(1)

users = data.get("users")
expected_permissions = data.get("expected_permissions")

if not isinstance(users, list) or not isinstance(expected_permissions, dict):
    print("ERROR: Missing or invalid users or expected_permissions.")
    raise SystemExit(1)

print("DBGuard - Permission Risk Report")
print("=" * 45)

for user in users:
    if not isinstance(user, dict):
        print("\nWARNING: Skipping an invalid user entry.")
        continue

    username = user.get("username", "Unknown")
    role = user.get("role")
    permissions = user.get("permissions")

    print(f"\nUser: {username} ({role})")

    if not isinstance(role, str) or role not in expected_permissions:
        print("Risk level: REVIEW REQUIRED")
        print("WARNING: Unknown or invalid role.")
        print("Recommended action: Check the user's assigned role.")
        continue

    if (
        not isinstance(permissions, list)
        or not all(isinstance(p, str) for p in permissions)
    ):
        print("Risk level: REVIEW REQUIRED")
        print("WARNING: Invalid permission data.")
        print("Recommended action: Check the user's permission list.")
        continue

    actual = set(permissions)
    expected = set(expected_permissions[role])

    excessive = actual - expected
    missing = expected - actual

    if excessive:
        print("Risk level: HIGH")
        print("Unexpected permissions:", ", ".join(sorted(excessive)))

        if "DELETE" in excessive:
            print("Why it matters: This user may delete database records.")
        if "UPDATE" in excessive:
            print("Why it matters: This user may change database records.")
        if "INSERT" in excessive:
            print("Why it matters: This user may add database records.")

        print("Recommended action: Review unexpected permissions.")
    else:
        print("Risk level: No unexpected permissions detected.")

    if missing:
        print("Missing expected permissions:", ", ".join(sorted(missing)))

print("\nAssessment complete.")
