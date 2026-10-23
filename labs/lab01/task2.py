"""Завдання 2: багаторівнева система контролю доступу (варіант 11)."""
from shared.student import STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "risk_manager": {"role": "risk_analyst", "clearance": 4,
                     "department": "Risk Management", "active": True},
    "business_analyst": {"role": "business_analyst", "clearance": 2,
                         "department": "Business", "active": True},
    "legal_counsel": {"role": "legal", "clearance": 3,
                      "department": "Legal", "active": True},
    "contractor_dev": {"role": "contractor", "clearance": 2,
                       "department": "Contract", "active": True},
    "obsolete_system": {"role": "legacy_system", "clearance": 1,
                        "department": "Legacy", "active": False},
}
RESOURCES = [
    ("risk_registers", 4), ("business_requirements", 2),
    ("legal_documents", 3), ("contract_code", 2),
    ("governance_framework", 4), ("meeting_minutes", 1),
    ("regulatory_reports", 3), ("executive_dashboards", 4),
    ("project_specs", 2), ("public_statements", 1),
]
SECURITY_LEVELS = (
    "Public", "Internal Use", "Restricted", "Highly Restricted",
)
BLOCKED_USERS = {"obsolete_system", "contract_expired", "legal_hold"}


def check_access(username, resource_level):
    """Повертає (дозволено, причина відмови)."""
    if username not in USERS:
        return False, "User not found"
    if username in BLOCKED_USERS:
        return False, "User is blocked"
    user = USERS[username]
    if not user["active"]:
        return False, "Account inactive"
    if user["clearance"] >= resource_level:
        return True, ""
    return False, "Insufficient clearance"


def main():
    """Вивід ресурсів і результатів перевірки доступу."""
    print(f"{STUDENT_NAME}, варіант {VARIANT_NUMBER}\n")
    print("Ресурси:")
    for name, level in RESOURCES:
        print(f"  {name:<25} {SECURITY_LEVELS[level - 1]}")

    print("\nПеревірка доступу:")
    usernames = list(USERS) + ["contract_expired"]
    for username in usernames:
        for name, level in RESOURCES:
            allowed, reason = check_access(username, level)
            verdict = "ALLOW" if allowed else f"DENY ({reason})"
            print(f"user={username} resource={name} -> {verdict}")


if __name__ == "__main__":
    main()
    