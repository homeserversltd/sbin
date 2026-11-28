"""House CA sign-csr stop."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/cert/house-ca/sign-csr", argv)
