# -*- encoding: utf-8 -*-
"""

 Encrypt Sender / Sign Receiver (ESSR) Client for healthKERI API
archie.core.essring package

"""

import asyncio
import json as fjson
import logging
import math
import random
from io import BytesIO

from urllib.parse import urlparse

import cbor
import pysodium
import requests
from keri import core

from keri.core import parsing, serdering, coring, counting
from keri.help import helping
from keri.peer import exchanging
from keri.kering import Vrsn_1_0

from ..core.tcp.client import AsyncTCPClient

logger = logging.getLogger(__name__)

CHUNK_SIZE = 65536


class APIClient:
    """
    Encrypt Sender / Sign Receiver (ESSR) Client for healthKERI API
    archie.core.essring package
    """

    def __init__(self, url, root, hby, hab, timeout: int = 10):

        self.hby = hby
        self.hab = hab
        self.url = url
        self.timeout = timeout

        up = urlparse(url)

        self.hostname = up.hostname
        self.port = up.port
        self.root = root

        # Create event and client
        self._client = None

    async def request(
        self,
        path="/",
        method="GET",
        data: bytes = None,
        json=None,
        files=None,
        headers=None,
        timeout: int = 30,
    ) -> requests.Response:
        """Execute request using HTTP tunneled over ESSR/TCP

        Parameters:
            path: (str): request path with optional query string after ?, defaults to "/"
            method: (str): HTTP request method, defaults to "GET"
            data (bytes): raw data
            json (dict): dictionary data to convert to JSON
            files (dict): multipart data
            headers (dict): HTTP headers
            timeout (int): timeout in seconds, defaults to 30 seconds, no timeout

        Returns:
            requests.Response: HTTP response

        """
        if hasattr(data, "encode"):
            data = data.encode("utf-8")

        headers = headers or {}

        req, reqid = self.http(path, method, data, json, files, headers)
        ims = self.essr(req)

        self._client = AsyncTCPClient(self.hostname, self.port)

        try:
            # Connect to the server
            if await self._client.connect():
                # Send the request
                if await self._client.send(ims):
                    logger.debug(
                        f"Request sent successfully to {self.hostname}:{self.port}"
                    )

                    # Wait for response with timeout
                    try:
                        rep, dig = await asyncio.wait_for(
                            self._read_and_parse(reqid, timeout=timeout),
                            timeout=timeout,
                        )
                        logger.debug(f"Response received and processed. {rep}")

                        response = requests.Response()
                        response.code = rep["reason"]
                        response.status_code = rep["status"]
                        for k, v in rep["headers"].items():
                            response.headers[k] = v

                        response.raw = BytesIO(rep["body"])

                        return response

                    except asyncio.TimeoutError:
                        logger.error(
                            f"Timeout after {timeout} seconds waiting for response"
                        )
                        raise TimeoutError(
                            f"Timeout after {timeout} seconds waiting for response"
                        )
                else:
                    logger.error(
                        f"Failed to send request to {self.hostname}:{self.port}"
                    )
                    raise ConnectionError(
                        f"Failed to send request to {self.hostname}:{self.port}"
                    )

            else:
                logger.error(f"Failed to connect to {self.hostname}:{self.port}")
                raise ConnectionError(
                    f"Failed to connect to {self.hostname}:{self.port}"
                )
        finally:
            # Ensure client is disconnected
            await self._client.disconnect()

    async def _read_and_parse(self, reqid, timeout: int = None):
        """Read and parse response from ESSR/TCP"""
        # Create parser with shared buffer
        ims = bytearray()
        parser = parsing.Parser(ims=ims, framed=True)

        ack = AckHandler()
        fwd = ForwardHandler(hby=self.hby, hab=self.hab, parser=parser)
        decoder = DecodeHandler(hby=self.hby, hab=self.hab)

        exc = exchanging.Exchanger(hby=self.hby, handlers=[ack, fwd, decoder])
        parser.exc = exc

        # Create the parser generator
        parsator = parser.onceParsator(ims=ims, framed=True, exc=exc)

        # Prime the generator (advance to first yield)
        try:
            next(parsator)
        except StopIteration:
            pass  # Parser completed immediately (shouldn't happen)

        # Read and parse continuously until we get our response
        while decoder.dig != reqid:
            try:
                # Receive chunk of data (like locksmith's client continuously filling rxbs)
                buf = await self._client.receive(4096)

                if not buf:
                    # Connection closed without receiving response
                    logger.error(f"Connection closed before receiving response {reqid}")
                    break

                # Append to shared buffer
                ims.extend(buf)

                # Drive the parser forward one step
                try:
                    next(parsator)
                except StopIteration:
                    # Parser finished this parse attempt
                    # Recreate and prime parser for next batch of messages
                    parsator = parser.onceParsator(ims=ims, framed=True, exc=exc)
                    next(parsator)

            except Exception as e:
                logger.error(f"Error reading/parsing data: {e}")
                return None, None

        return (decoder.rep, decoder.dig)

    async def close(self):
        if self._client:
            await self._client.disconnect()

    def http(
        self, path, method, data: bytes = None, json=None, files=None, headers=None
    ):

        if data is not None:
            raw = data
            headers["CONTENT-LENGTH"] = len(raw)
        elif json is not None:
            raw = fjson.dumps(json).encode("utf-8")
            headers["CONTENT-TYPE"] = "application/json"
            headers["CONTENT-LENGTH"] = len(raw)
        elif files is not None:
            boundary = "____________{0:012x}".format(
                random.randint(123456789, 0xFFFFFFFFFFFF)
            )

            form_parts = []
            # mime parts always start with --
            for k, (file, data, contentType) in files.items():
                if hasattr(data, "decode"):
                    data = data.decode("utf-8")

                form_parts.append(
                    "\r\n--{0}\r\nContent-Disposition: "
                    'form-data; name="{1}"\r\n'
                    "Content-Type: {2}; charset=utf-8\r\n"
                    "\r\n{3}".format(boundary, k, contentType, data)
                )
            form_parts.append("\r\n--{0}--".format(boundary))
            form = "".join(form_parts)
            raw = form.encode("utf-8")
            headers["CONTENT-TYPE"] = "multipart/form-data; boundary={0}".format(
                boundary
            )
            headers["CONTENT-LENGTH"] = len(raw)
        else:
            raw = b""

        headers["ESSR-SENDER"] = self.hab.pre
        reqid = coring.randomNonce()

        pp = urlparse(path)
        path = pp.path
        method = method
        query = pp.query

        # Must create an exn `/http/req` route
        payload = http_request(
            scheme="HTTP",  # Hard code because it doesn't matter
            method=method,
            host=self.hostname,
            port=self.port,
            path=path,
            query_string=query,
            remote_addr="",
            headers=headers,
            content_type=(
                headers["CONTENT-TYPE"] if "CONTENT-TYPE" in headers else "text/plain"
            ),
            raw=raw,
            reqid=reqid,
        )

        if "CONTENT-LENGTH" in headers:
            payload["contentLength"] = headers["CONTENT-LENGTH"]

        return dict(i=self.hab.pre, a=payload), reqid

    def essr(self, payload):
        rkever = self.hab.kevers[self.root]

        # convert signing public key to encryption public key
        pubkey = pysodium.crypto_sign_pk_to_box_pk(rkever.verfers[0].raw)
        raw = pysodium.crypto_box_seal(cbor.dumps(payload), pubkey)
        diger = coring.Diger(ser=raw, code=coring.MtrDex.Blake3_256)

        exn, _ = exchanging.exchange(
            route="/essr/req",
            diger=diger,
            sender=self.hab.pre,
            recipient=rkever.prefixer.qb64,  # Must sign receiver
            date=helping.nowIso8601(),
            version=Vrsn_1_0,
        )

        ims = self.hab.endorse(serder=exn, pipelined=False)

        size = len(raw)
        chunks = math.ceil(size / CHUNK_SIZE)
        ims.extend(
            core.Counter(
                code=counting.CtrDex_1_0.ESSRPayloadGroup, count=chunks, gvrsn=Vrsn_1_0
            ).qb64b
        )
        for idx in range(chunks):
            start = idx * CHUNK_SIZE
            end = start + CHUNK_SIZE
            texter = coring.Matter(raw=raw[start:end], code=coring.MtrDex.Bytes_L0)
            ims.extend(texter.qb64b)

        fwd, atc = exchanging.exchange(
            route="/fwd",
            modifiers=dict(),
            payload=dict(src=exn.ked["i"], dest=exn.ked["rp"], ctx={}),
            embeds=dict(evt=ims),
            sender=self.hab.pre,
        )

        ims = self.hab.endorse(serder=fwd, last=False, pipelined=False)
        ims.extend(atc)
        self.hab.db.epath.rem(keys=(fwd.said,))

        return ims


class AckHandler:
    """
    Handler for acknowledgement `exn` messages used to ack the reply of other exns

    on
        {
           "v": "KERI10JSON00011c_",                               // KERI Version String
           "t": "exn",                                             // peer to peer message ilk
           "dt": "2020-08-22T17:50:12.988921+00:00"
           "r": "/ack",
           "q": {
              "pre": "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU",
              "topic": "delegate"
            }
           "a": {},
           "p": "ECgaLXUw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZBp64A"
        }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA

    """

    resource = "/ack"

    def __init__(self):
        """
        Handler for acknowledgement `exn` messages used to ack the reply of other exns

        """
        pass

    @staticmethod
    def handle(serder, attachments=None):
        """Do route specific processsing of IPEX protocol exn messages

        Parameters:
            serder (Serder): Serder of the IPEX protocol exn message
            attachments (list): list of tuples of root pathers and CESR SAD path attachments to the exn event

        """

        said = serder.ked["d"]
        dig = serder.ked["p"]

        logger.debug(f"ack={said} received for exn message {dig}")


class ForwardHandler:
    """
    Handler for forward `exn` messages used to envelope other KERI messages intended for another recipient.
    This handler acts as a mailbox for other identifiers and stores the messages in a local database.

    on
        {
           "v": "KERI10JSON00011c_",                               // KERI Version String
           "t": "exn",                                             // peer to peer message ilk
           "dt": "2020-08-22T17:50:12.988921+00:00"
           "r": "/fwd",
           "q": {
              "pre": "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU",
              "topic": "delegate"
            }
           "a": '{
              "v":"KERI10JSON000154_",
              "t":"dip",
              "d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI",
              "i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI",
              "s":"0",
              "kt":"1",
              "k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],
              "n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU",
              "bt":"0",
              "b":[],
              "c":[],
              "a":[],
              "di":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"
           }
        }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA

    """

    resource = "/fwd"

    def __init__(self, hby, hab, parser, params=None):
        """

        Parameters:
            hab (Hab): database environment
            parser (Parser): message parser

        """
        self.hby = hby
        self.hab = hab

        self.parser = parser
        self.said = None
        self.payload = None

        self.params = params or {}

    def handle(self, serder, attachments=None):
        """Do route specific processsing of IPEX protocol exn messages

        Parameters:
            serder (Serder): Serder of the IPEX protocol exn message
            attachments (list): list of tuples of root pathers and CESR SAD path attachments to the exn event

        """
        embeds = serder.ked["e"]
        if attachments:
            ims = bytearray()
            for pather, atc in attachments:
                sad = pather.resolve(embeds)
                embed = serdering.SerderKERI(sad=sad)
                ims.extend(embed.raw)
                ims.extend(atc)
        else:
            return

        self.parser.parseOne(ims=ims)


class DecodeHandler:
    """
    Handler for essr encoded `exn` messages used to secure other messages intended for another recipient.
    This handler verifies the signer is correctly encryped in the payload and that the recipient was signed

    on
        {
           "v": "KERI10JSON00011c_",                               // KERI Version String
           "t": "exn",                                             // peer to peer message ilk
           "d": "EAhDiMFIINHBIn139nSG7QlNj7Sa2YHdZDIvzRYylQeE",
           "dt": "2020-08-22T17:50:12.988921+00:00"
           "r": "/essr/req",
           "q": {
            }
           "a": '{
              "d": "6AA-AABWcUNwTFZON3I4WV9tV1VRSDFpWS10WW5RMjVFb3V4SWtheGxHZHRreWdRM1oxYzVx...",
              "i": "EAhDiMFIINHBIn139nSG7QlNj7Sa2YHdZDIvzRYylQeE"
           }
        }-AABAA1o61PgMhwhi89FES_vwYeSbbWnVuELV_jv7Yv6f5zNiOLnj1ZZa4MW2c6Z_vZDt55QUnLaiaikE-d_ApsFEgCA

    """

    resource = "/essr/req"

    def __init__(self, hby, hab, params=None):
        """

        Parameters:
            hby (Habery): Identifier database environment and factory
            hab (Hab): Identifier class for signing and decryption

        """
        self.hby = hby
        self.hab = hab

        self.rep = None
        self.dig = None

        self.params = params or {}

    def handle(self, serder, attachments=None, essr=None):
        """

        This handler decrypts the the encrypted payload, verifies that the sender is in the encrypted payload
        and verifies that the recipient AID was signed as part of the package

        Parameters:
            serder (Serder): Serder of the IPEX protocol exn message
            attachments (list): list of tuples of root pathers and CESR SAD path attachments to the exn event
            essr (bytes):  essr attached bytes

        """

        # Get the encrypted payload
        if essr:
            data = essr
        else:
            enc = serder.ked["a"]["d"]
            data = coring.Texter(qb64=enc).raw

        rp = serder.ked["rp"]

        # Ensure the signed receiver is us
        if self.hab.pre != rp:
            logger.error(
                f"dessr: invalid /essr/req message, rp={rp} not one of us={self.hab.pre}"
            )
            return

        # Decrypt it with our dest hab
        raw = self.hab.decrypt(data)
        req = cbor.loads(raw)

        payload = req["a"]

        rep = payload["response"]
        atc = bytearray(payload["atc"].encode("utf-8"))

        body = bytearray()

        if atc:
            counter = counting.Counter(qb64b=atc, strip=True)
            for _ in range(counter.count):
                body.extend(core.Texter(qb64b=atc, strip=True).raw)

        rep["body"] = body

        self.rep = rep
        self.dig = payload["reqid"]

        self.hab.db.essrs.rem(keys=(serder.said,))
        self.hab.db.epath.rem(keys=(serder.said,))


def http_request(
    scheme,
    method,
    host,
    port,
    path="/",
    raw=b"",
    query_string="",
    remote_addr="",
    headers=None,
    content_type="text/html",
    content_length=None,
    reqid="",
):

    headers = headers if headers is not None else dict()

    if raw:
        dig = core.Diger(ser=raw, code=core.MtrDex.Blake3_256).qb64
    else:
        dig = ""

    payload = dict(
        scheme=scheme,
        method=method,
        host=host,
        port=port,
        path=path,
        query=query_string,
        remote=remote_addr,
        headers=headers,
        contentType=content_type,
        body=dig,
        reqid=reqid,
    )

    if content_length is not None:
        payload["contentLength"] = content_length
    elif raw:
        payload["contentLength"] = len(raw)

    ims = bytearray()
    size = len(raw)
    chunks = math.ceil(size / CHUNK_SIZE)
    if chunks:
        ims.extend(
            counting.Counter(
                code=counting.CtrDex_1_0.ESSRPayloadGroup, count=chunks, gvrsn=Vrsn_1_0
            ).qb64b
        )
        for idx in range(chunks):
            start = idx * CHUNK_SIZE
            end = start + CHUNK_SIZE
            texter = coring.Matter(raw=raw[start:end], code=coring.MtrDex.Bytes_L0)
            ims.extend(texter.qb64b)

    return dict(r="/http/req", request=payload, atc=ims.decode("utf-8"))
