import logging
import sys
from .connection import Connection

if __name__ == '__main__':
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format="[%(asctime)s] %(levelname)s: %(message)s",
    )
    Connection("45.32.226.24", 1776)
    # Connection("51.91.29.156", 32837)
