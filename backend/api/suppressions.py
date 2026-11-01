"""Mute rules: a NULL field means "any"; matched at read and broadcast time, so muted alerts stay stored."""
import ipaddress

FIELDS = ("src_ip", "dst_ip", "dst_port", "attack_type")


def validate(rule: dict) -> dict:
    """Return the rule's four fields, cleaned; raise ValueError for an all-"any" rule or a bad value."""
    clean = {f: rule.get(f) for f in FIELDS}
    if all(v is None for v in clean.values()):
        raise ValueError("A rule needs at least one field; an all-'any' rule would mute everything")
    for f in ("src_ip", "dst_ip"):
        if clean[f] is not None:
            clean[f] = str(ipaddress.ip_address(clean[f]))  # ValueError on anything that isn't an IP
    if clean["dst_port"] is not None and not 0 <= int(clean["dst_port"]) <= 65535:
        raise ValueError("dst_port must be 0-65535")
    if clean["attack_type"] is not None and not 0 < len(clean["attack_type"]) <= 64:
        raise ValueError("attack_type must be 1-64 characters")
    return clean


def suppressed_by(rules: list[dict], alert: dict) -> int | None:
    """Rules are kept sorted by id, so the lowest-id match wins."""
    for rule in rules:
        if all(rule[f] is None or rule[f] == alert[f] for f in FIELDS):
            return rule["id"]
    return None
