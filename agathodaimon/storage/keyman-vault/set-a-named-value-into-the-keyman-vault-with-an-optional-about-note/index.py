"""Put a named value into Keyman from an envelope or flat JSON request."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("keyman/secret/put", argv, band="storage/keyman-vault/set-a-named-value-into-the-keyman-vault-with-an-optional-about-note")
