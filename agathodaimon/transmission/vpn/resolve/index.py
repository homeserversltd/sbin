"""Resolve the bound Transmission VPN, namespace and portal row without mutation."""
from agathodaimon.transmission import runtime as rt

SCHEMA = "caduceus.transmission.vpn.resolve.v1"


def main(argv=None):
    del argv
    request = None
    try:
        request = rt.read_request(known_fields=("provider",), declared_flags=("vpn",))
        options, _ = rt.resolve_bound_vpn(request)
        result = rt.receipt(SCHEMA, options["provider"])
        result.update({key: options[key] for key in ("provider", "protocol", "region", "dip", "dns", "rescan")})
        result.update(holdUnit=rt.HOLD_UNIT.format(options["provider"]), nativeUnit=rt.NATIVE_UNIT,
                      rpcPort=rt.portal_port(), namespacePresent=rt.VPN_NAMESPACE in rt.namespace_names(),
                      ok=True, firstMissingSignal="none", mutationPerformed=False)
    except Exception as failure:
        result = rt.failure_receipt(SCHEMA, failure)
    result = rt.finish(result, request)
    if rt._journal_stdout():
        return 0 if result.get("ok") is True else 1
    return rt.print_receipt(result)
