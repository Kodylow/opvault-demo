import os

# Override this if you're not running with docker-compose.
BITCOIN_RPC_URL = os.environ.get("BITCOIN_RPC_URL", "http://bitcoin:18443")

# Default sats to use for fees.
# TODO make this configurable, or smarter.
FEE_VALUE_SATS: int = 20_000
