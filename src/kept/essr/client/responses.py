# -*- encoding: utf-8 -*-
"""
KERI-ESSR
kept.essr.client.responses package

"""

from kept.core.exceptions import ESSRStatusError


class Response:

    def __init__(self, sender: str, payload: dict):
        self.sender = sender
        self._payload = payload

        self._content = payload["body"]
        self._headers = {
            key.decode("utf-8"): val.decode("utf-8")
            for (key, val) in payload["headers"]
        }

    @property
    def headers(self) -> dict:
        return self._headers

    @property
    def status_code(self) -> int:
        return int(self._payload["status"])

    def raise_for_status(self):
        status_code = self.status_code
        status_class = status_code // 100

        if status_class == 2:
            return self

        error_types = {
            1: "Informational response",
            3: "Redirect response",
            4: "Client error",
            5: "Server error",
        }

        raise ESSRStatusError(status_code, error_types[status_code])

    async def aread(self) -> bytes:
        """
        Read and return the response content.
        """
        return self._content

    def read(self) -> bytes:
        """
        Read and return the response content.
        """
        return self._content
