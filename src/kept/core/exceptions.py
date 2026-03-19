# -*- encoding: utf-8 -*-
"""
KERI-ESSR
kept.essr.core.exceptions package

"""


class ESSRStatusError(Exception):
    """Raised when the ESSR server responds with an error status."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
