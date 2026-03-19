import math
import random

import cbor
import pysodium
from keri import kering, help, core
from keri.core import coring, serdering, MtrDex
from keri.core.counting import CtrDex_1_0
from keri.db import dbing
from keri.help import helping
from keri.kering import ConfigurationError
from keri.peer import exchanging

from kept.db import basing

logger = help.ogler.getLogger()

CHUNK_SIZE = 65536


class CryptSigner:

    def __init__(self, hby, hab, rt=None, encryption_target=None):
        """Factory for creating delegates for a give Delegator Hab1

        Parameters:
            hby (Habery):  database environment and Hab factory
            rt (RouteTable): RACK database environment
            hab (Hab): delegator's hab

        """
        self.hby = hby
        self._hab = hab
        self.rt = (
            rt
            if rt is not None
            else basing.RouteTable(name=hby.name, reopen=True, temp=hby.temp)
        )

        self.encryption_target = encryption_target
        self.scan = set()

    def make(
        self,
        count=10,
        algo="randy",
        salt=None,
        icount=1,
        isith="1",
        ncount=1,
        nsith="1",
    ):
        """Create delegates from the delegator

        Parameters:
            count (int):  the number of delegates to create
            algo (str):  key generation algo, "salty" or "randy"
            salt: (str): 21 character length key generation salt
            icount (int): number of signing keys to create per delegate
            isith: (str): signing threshold
            ncount (int): number of rotation keys to create per delegate
            nsith: (str): rotation threshold

        Returns:
            list:  a list of delegate Habs

        """
        start = 0
        for hab in self.hby.habs.values():
            if hab.name.startswith(hab.name):
                start += 1

        anchors = list()
        delegates = list()
        for idx in range(count):
            alias = f"{self._hab.name}-{idx + start}"

            if self.hby.habByName(alias) is not None:
                raise ValueError(
                    f"{alias} is already in use, please pick another alias prefix"
                )

            kwargs = dict()
            kwargs["algo"] = algo
            if algo == "salty":
                if salt is None or len(salt) != 24:
                    raise ValueError("Salt is required and must be 24 characters long")

                kwargs["salt"] = salt
                kwargs["icount"] = int(icount)
                kwargs["isith"] = int(isith)
                kwargs["ncount"] = int(ncount)
                kwargs["nsith"] = int(nsith)

            elif algo == "randy":
                kwargs["salt"] = None
                kwargs["icount"] = int(icount)
                kwargs["isith"] = int(isith)
                kwargs["ncount"] = int(ncount)
                kwargs["nsith"] = int(nsith)

            kwargs["delpre"] = self._hab.pre
            kwargs["estOnly"] = False

            hab = self.hby.makeHab(name=alias, **kwargs)
            delegates.append(hab)
            anchors.append(dict(i=hab.pre, s="0", d=hab.pre))
            self.rt.dlgs.add(keys=(self._hab.pre,), val=hab.pre)

        self._hab.interact(data=anchors)

        for anchor in anchors:
            seqner = coring.Seqner(sn=self._hab.kever.serder.sn)
            couple = seqner.qb64b + self._hab.kever.serder.saidb
            dgkey = dbing.dgKey(anchor["i"], anchor["d"])
            self.hby.db.setAes(
                dgkey, couple
            )  # authorizer event seal (delegator/issuer)

        return delegates

    def delegates(self, aid):
        return self.rt.dlgs.get(keys=(aid,))

    def scan_for_delegates(self, aid):
        if aid not in self.scan:
            scan_for_delegates(self.hby, self.rt, aid)
            self.scan.add(aid)

    @property
    def pre(self):
        return self._hab.pre

    def hab(self, aid):
        if (
            delegate := self.rt.cur.get(keys=(aid,))
        ) is not None and delegate in self.hby.habs:
            return self.hby.habs[delegate]

        # We don't have a current signing delegate assigned, lets see if we can assign one.
        elif len(delegates := self.delegates(aid)) > 0:
            if (
                delegates
            ):  # if we have defined delegates, assign the first one as our current signer
                delegate = delegates[0]
                if delegate in self.hby.habs:
                    self.rt.cur.pin(keys=(aid,), val=delegate)
                    return self.hby.habs[delegate]

        elif aid in self.hby.habs:
            return self.hby.habs[aid]

        raise kering.ConfigurationError(f"Unable to find Hab for {aid}")

    def kever(self, aid):
        delegates = self.delegates(aid)
        if delegates:
            delegate = random.choice(delegates)
            if delegate in self.hby.kevers:
                return self.hby.kevers[delegate]
            else:
                raise kering.ConfigurationError(f"Unable to find kever for {aid}")
        elif aid in self.hby.kevers:
            return self.hby.kevers[aid]
        else:
            raise kering.ConfigurationError(f"Unable to find kever for {aid}")

    def encode(self, path, payload, target=None, said=None):
        hab = self.hab(self._hab.pre)  # Signer is always hardcoded

        payload = dict(i=hab.pre, **payload)

        encryption_target = (
            target if target is not None else self.encryption_target
        )  # Must extract the encryption

        # target from the message context from DESSR or get is from self.encryption_target
        if encryption_target is None:
            raise ConfigurationError("Unable to determine encryption target")

        rkever = self.kever(encryption_target)
        if rkever is None:
            raise ConfigurationError(
                f"Unable to find kever for encryption target {encryption_target}"
            )

        # convert signing public key to encryption public key
        pubkey = pysodium.crypto_sign_pk_to_box_pk(rkever.verfers[0].raw)
        raw = pysodium.crypto_box_seal(cbor.dumps(payload), pubkey)
        diger = coring.Diger(ser=raw, code=MtrDex.Blake3_256)

        kwargs = dict()
        if said is not None:
            kwargs["dig"] = said

        exn, _ = exchanging.exchange(
            route=path,  # The return_route of original message
            diger=diger,
            sender=hab.pre,
            recipient=rkever.prefixer.qb64,  # Must sign receiver
            date=helping.nowIso8601(),
            **kwargs,
        )

        ims = hab.endorse(serder=exn, pipelined=False)

        size = len(raw)
        chunks = math.ceil(size / CHUNK_SIZE)
        ims.extend(
            core.Counter(
                code=CtrDex_1_0.ESSRPayloadGroup, count=chunks, gvrsn=kering.Vrsn_1_0
            ).qb64b
        )
        for idx in range(chunks):
            start = idx * CHUNK_SIZE
            end = start + CHUNK_SIZE
            texter = coring.Matter(raw=raw[start:end], code=MtrDex.Bytes_L0)
            ims.extend(texter.qb64b)

        hab.psr.parseOne(ims=bytes(ims))

        hab.db.essrs.rem(keys=(exn.said,))
        hab.db.epath.rem(keys=(exn.said,))
        self.rt.encs.add(keys=(hab.kever.serder.said,), val=exn.said)

        return ims

    def rotate_signer(self, aid):
        delegates = self.delegates(aid)
        if not delegates:
            raise kering.ConfigurationError(f"No delegates assigned for {aid}")

        if not (delegate := self.rt.cur.get(keys=(aid,))):
            if (
                delegates
            ):  # if we have defined delegates, assign the first one as our current signer
                delegate = delegates[0]
                if delegate in self.hby.habs:
                    self.rt.cur.pin(keys=(aid,), val=delegate)
        else:
            try:
                idx = delegates.index(delegate)
            except ValueError:
                delegate = delegates[0]
                if delegate in self.hby.habs:
                    self.rt.cur.pin(keys=(aid,), val=delegate)
            else:
                idx = (idx + 1) % len(delegates)
                delegate = delegates[idx]
                if delegate in self.hby.habs:
                    self.rt.cur.pin(keys=(aid,), val=delegate)


def scan_for_delegates(hby, rt, delegator):
    cloner = hby.db.clonePreIter(pre=delegator, fn=0)  # create iterator at 0
    rt.dlgs.rem(keys=(delegator,))
    for msg in cloner:
        srdr = serdering.SerderKERI(raw=msg)
        process_delegator_event_seals(hby, rt, srdr)


def process_delegator_event_seals(hby, rt, srdr):
    delegator = srdr.pre
    for anchor in srdr.seals:
        if (
            "i" not in anchor and "s" not in anchor and "d" not in anchor
        ):  # Event seal anchor
            continue

        delegate = anchor["i"]
        if (
            anchor["s"] != "0" or delegate != anchor["d"]
        ):  # Ensure this is an inception anchor
            continue

        delegate_kever = hby.kevers[delegate]

        # Check for accidental registration of non-delegate or for a delegate that was neutered.
        if delegate_kever.delpre != delegator or not delegate_kever.ndigers:
            continue

        rt.dlgs.add(keys=(delegator,), val=delegate)

        logger.info(f"Signer {delegate} added for delegator {delegator}")
