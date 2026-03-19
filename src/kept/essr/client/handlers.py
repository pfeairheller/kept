# -*- encoding: utf-8 -*-
"""
KERI-ESSR
kept.essr.client.handlers package

"""

import cbor2 as cbor
from keri.help import ogler
from keri.core import coring

logger = ogler.getLogger()


class ESSRHandler:
    def __init__(self, crypt_signer, resource, response_event):
        self.crypt_signer = crypt_signer
        self._resource = resource
        self.encryption_target = crypt_signer.encryption_target
        self.response_event = response_event

        self.sender = None
        self.payload = None

    @property
    def resource(self):
        return self._resource

    def handle(self, serder, attachments=None, essr=None):
        """

        This handler decrypts the the encrypted payload, verifies that the sender is in the encrypted payload
        and verifies that the recipient AID was signed as part of the package

        Parameters:
            serder (Serder): Serder of the IPEX protocol exn message
            attachments (list): list of tuples of root pathers and CESR SAD path attachments to the exn event
            essr (bytes):  essr attached bytes

        """
        if essr:
            data = essr
        else:
            enc = serder.ked["a"]["d"]
            data = coring.Texter(qb64=enc).raw

        rp = serder.ked["rp"]
        hab = self.crypt_signer.hab(rp)
        # Ensure the signed receiver is us

        if hab is None or not (
            hab.pre == self.crypt_signer.pre
            or hab.kever.delpre == self.crypt_signer.pre
        ):
            print(
                f"essr msg: invalid /essr/req message, rp={rp} not one of us={self.crypt_signer.pre}"
            )
            self.response_event.set()
            return

        # Decrypt it with our dest hab
        decrypted = hab.decrypt(data)
        req = cbor.loads(decrypted)

        # Ensure that the encrypted sender is the one that also signed it
        sender = req["i"]
        payload = req["a"]

        if sender != serder.ked["i"]:
            print(
                f"dessr: invalid essr req message, encrypted sender={sender} not equal to message signer={serder.ked['i']}"
            )
            self.response_event.set()
            return

        # Ensure that we know about this sender
        if sender not in hab.kevers:
            print(f"essr-handler: unknown src aid={sender}")
            self.response_event.set()
            return

        self.sender = sender
        self.payload = payload

        # Signal that response was received
        self.response_event.set()
