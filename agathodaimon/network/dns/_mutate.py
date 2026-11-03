"""Shared managed DNS mutation operations for the alias and fixed stops."""
from pathlib import Path

from agathodaimon.network.dns._manager import DnsError


def device_name(manager, action, hostname, ip):
    receipt = manager.create_device_name(hostname, ip) if action == "create" else manager.remove_device_name(hostname, ip)
    receipt |= {"schema": "caduceus.network.dns.v1", "actuator": f"network.dns.device_name.{action}", "ok": True, "firstMissingSignal": "none"}
    return receipt


def alias(manager, action, label, hostname):
    receipt = manager.create_alias(label, hostname) if action == "create" else manager.remove_alias(label, hostname)
    receipt |= {"schema": "caduceus.network.dns.v1", "actuator": f"network.dns.alias.{action}", "ok": True, "firstMissingSignal": "none"}
    return receipt


def apply(manager, metadata):
    return manager.apply(metadata)


def stop_apply(manager, target, drop_in, dry_run):
    # The stop requires the explicit managed file path, unlike the legacy alias.
    if not isinstance(target, str) or not Path(target).is_absolute() or Path(target) != manager.target:
        raise DnsError("dns-target-not-admitted")
    target = manager.TARGET_NAME
    if not isinstance(dry_run, bool):
        raise DnsError("dns-dry-run-invalid")
    metadata = {"target": target, "dropIn": drop_in, "dryRun": dry_run}
    if not dry_run:
        return apply(manager, metadata)
    # A stop's dry-run is a read-only plan, not the legacy staged validation.
    path = manager._safe_target(target)
    candidate = manager._validate_payload(drop_in)
    previous = path.read_bytes() if path.exists() else None
    return {"schema": "caduceus.network.dns.v1", "action": "plan-managed-drop-in",
            "target": str(path), "beforeHash": manager._digest(previous),
            "afterHash": manager._digest(candidate), "stagedValidation": False,
            "liveValidation": False, "reload": "not-run", "rollback": "not-needed",
            "mutationPerformed": False, "ok": True, "firstMissingSignal": "none"}
