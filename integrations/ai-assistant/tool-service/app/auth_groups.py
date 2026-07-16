"""Shared auth-failure and brute-force filter constants (V3.7)."""

AUTH_FAILURE_GROUPS: tuple[str, ...] = (
    "authentication_failed",
    "authentication_failures",
    "win_authentication_failed",
)

BRUTE_FORCE_MITRE = "T1110"

AUTH_FAILURE_KUERY = " or ".join(f"rule.groups: {g}" for g in AUTH_FAILURE_GROUPS)
