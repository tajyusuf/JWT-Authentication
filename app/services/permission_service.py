ROLE_PERMISSIONS = {
    "admin": ["users:read", "users:write", "sessions:read", "sessions:revoke"],
    "user": ["sessions:read", "sessions:revoke"],
}


def permissions_for_role(role: str) -> list[str]:
    return ROLE_PERMISSIONS.get(role, [])

