"""Read the MACs held by the firewall's owned nftables file."""
from pathlib import Path
import re


DEFAULT_NFT = Path("/etc/nftables.d/caduceus-child-filter.nft")
ETHER_SOURCE = re.compile(r"\bether\s+saddr\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})(?![0-9a-f:])", re.IGNORECASE)


def held_macs(path: str | Path = DEFAULT_NFT) -> set[str]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return set()
    return {match.lower() for match in ETHER_SOURCE.findall(text)}
