# -*- encoding: utf-8 -*-
"""
KERI-ESSR
kept.essr.client.requests package

"""

import json as fjson
import math
import random


from keri import core
from keri.core import counting, coring

from keri.help import ogler
from keri.kering import Vrsn_1_0

logger = ogler.getLogger()

CHUNK_SIZE = 65536


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


def essr_request(
    method,
    host,
    port,
    return_route,
    raw=b"",
    params: dict = None,
    remote_addr="",
    headers=None,
    content_type="text/html",
    content_length=None,
    nonce="",
):

    headers = headers if headers is not None else dict()

    if raw:
        dig = core.Diger(ser=raw, code=core.MtrDex.Blake3_256).qb64
    else:
        dig = ""

    payload = dict(
        method=method,
        host=host,
        port=port,
        return_route=return_route,
        params=params,
        remote=remote_addr,
        headers=headers,
        contentType=content_type,
        body=dig,
        nonce=nonce,
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

    return payload, ims.decode("utf-8")


def http(
    hostname,
    port,
    path,
    params,
    return_route,
    method="GET",
    data: bytes = None,
    json: dict = None,
    files=None,
    headers=None,
):

    if data is not None:
        raw = data
        headers["CONTENT-LENGTH"] = str(len(raw))
    elif json is not None:
        raw = fjson.dumps(json).encode("utf-8")
        headers["CONTENT-TYPE"] = "application/json"
        headers["CONTENT-LENGTH"] = str(len(raw))
    elif files is not None:
        boundary = "____________{0:012x}".format(
            random.randint(123456789, 0xFFFFFFFFFFFF)
        )

        formParts = []
        # mime parts always start with --
        for k, (file, data, contentType) in files.items():
            if hasattr(data, "decode"):
                data = data.decode("utf-8")

            formParts.append(
                "\r\n--{0}\r\nContent-Disposition: "
                'form-data; name="{1}"\r\n'
                "Content-Type: {2}; charset=utf-8\r\n"
                "\r\n{3}".format(boundary, k, contentType, data)
            )
        formParts.append("\r\n--{0}--".format(boundary))
        form = "".join(formParts)
        raw = form.encode("utf-8")
        headers["CONTENT-TYPE"] = "multipart/form-data; boundary={0}".format(boundary)
        headers["CONTENT-LENGTH"] = str(len(raw))
    else:
        raw = b""

    nonce = coring.randomNonce()

    method = method

    # Must create an exn `/http/req` route
    payload, body = essr_request(
        method=method,
        host=hostname,
        port=port,
        return_route=return_route,
        params=params,
        remote_addr="",
        headers=headers,
        content_type=(
            headers["CONTENT-TYPE"] if "CONTENT-TYPE" in headers else "text/plain"
        ),
        raw=raw,
        nonce=nonce,
    )

    if "CONTENT-LENGTH" in headers:
        payload["contentLength"] = headers["CONTENT-LENGTH"]

    return dict(a=payload, body=body)
