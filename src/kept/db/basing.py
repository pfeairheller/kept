# -*- encoding: utf-8 -*-
"""
kept.db.basing module

"""

from keri.core import coring
from keri.db import dbing, subing


class RouteTable(dbing.LMDBer):
    TailDirPath = "keri/rt"
    AltTailDirPath = ".keri/rt"
    TempPrefix = "rt"

    def __init__(self, name="routetable", headDirPath=None, reopen=True, **kwa):
        """

        Parameters:
            headDirPath:
            perm:
            reopen:
            kwa:
        """
        self.srcs = None

        self.gators = None
        self.dsts = None
        self.dlgs = None
        self.rtrd = None

        self.cur = None
        self.encs = None
        self.ancs = None

        self.nots = None
        self.rtrs = None
        self.lscn = None

        self.routes = dict()

        super(RouteTable, self).__init__(
            name=name, headDirPath=headDirPath, reopen=reopen, **kwa
        )

    def reopen(self, **kwa):
        """Reopen database and initialize sub-dbs"""
        super(RouteTable, self).reopen(**kwa)

        # Tracking current delegates available for given delegator keyed by delegator AID
        self.dlgs = subing.IoSetSuber(db=self, subkey="dlgs.")

        # Tracking retired delegates no longer available for given delegator keyed by delegator AID
        self.rtrd = subing.IoSetSuber(db=self, subkey="rtrd.")

        # Current in use delegate for a given delegator keyed by delegator AID
        self.cur = subing.Suber(db=self, subkey="cur.")

        # Current set of encoded but not anchored essr exn messages
        self.encs = subing.IoSetSuber(db=self, subkey="encs.")

        # Current set of anchoring interaction events created
        self.ancs = subing.CatCesrIoSetSuber(
            db=self, subkey="ancs.", klas=(coring.Diger, coring.Diger)
        )

        self.reload()
        return self.env

    def reload(self):
        pass

    def cnt_ancs(self, keys):
        vals = []
        for item in self.ancs.getItemIter(keys=keys):
            vals.append(item)

        return len(vals)
