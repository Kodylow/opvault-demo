import logging
import os

loglevel = "DEBUG"  # if os.environ.get("DEBUG") else "INFO"
log = logging.getLogger("opvault")
logging.basicConfig(filename="opvault-demo.log", level=loglevel)
