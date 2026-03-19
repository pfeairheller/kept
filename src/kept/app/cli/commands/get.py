# -*- encoding: utf-8 -*-
"""
heki.app.cli module

"""

import argparse
import asyncio
from urllib.parse import urlparse, parse_qs

from keri import help
from keri import kering
from keri.app import connecting
from keri.app.cli.common import existing

from kept.core.authentication import CryptSigner
from kept.essr.client import AsyncClient

parser = argparse.ArgumentParser(
    description="Perform an kurl (essr encoded) request against the provided URL."
)
parser.set_defaults(handler=lambda args: asyncio.run(launch(args)))
parser.add_argument("url", help="ESSR URL to process", metavar="<url>")
parser.add_argument(
    "--name",
    "-n",
    help="keystore name and file location of KERI keystore",
    required=False,
    default="owl",
)
parser.add_argument("--alias", action="store", required=False, default="owl")
parser.add_argument(
    "--base",
    "-b",
    help="additional optional prefix to file location of KERI keystore",
    required=False,
    default="",
)
parser.add_argument(
    "--passcode",
    "-p",
    help="21 character encryption passcode for keystore (is not saved)",
    dest="bran",
    default=None,
)  # passcode => bran
parser.add_argument("--remote", action="store", required=False, default=None)

parser.add_argument(
    "--json", "-j", help="JSON data to send with request", type=str, default=None
)
parser.add_argument(
    "--header",
    "-H",
    help='HTTP header in format "Name: Value"',
    action="append",
    default=[],
)
parser.add_argument(
    "--files",
    "-F",
    help='HTTP header in format "Name: Value"',
    action="append",
    default=[],
)
parser.add_argument(
    "--data", "-d", help="Form data to send with request", type=str, default=None
)
parser.add_argument(
    "--timeout",
    "-t",
    help="Timeout in seconds for waiting for response",
    type=int,
    default=10,
)

logger = help.ogler.getLogger()


async def launch(args):
    # Arguments from the command line
    name = args.name
    alias = args.alias
    bran = args.bran

    parsed = urlparse(args.url)

    # Override name, alias and passcode if provided in the URL
    if parsed.username:
        name = parsed.username

    if parsed.password:
        if ":" in parsed.password:
            alias, bran = parsed.password.split(":", maxsplit=1)
        else:
            alias = parsed.password

    with existing.existingHab(name=name, alias=alias, base=args.base, bran=bran) as (
        hby,
        hab,
    ):
        if not hab:
            raise kering.ConfigurationError(
                f"Identifier '{alias}' must already exist, exiting."
            )
        org = connecting.Organizer(hby=hby)

        # Determine the remote identifier to use, start with the --remote argument, then fallback to the hostname
        root = args.remote

        if not root:
            root = parsed.hostname

        target = None
        if root in hby.kevers:
            target = hby.kevers[root].pre
        else:
            contacts = org.find("alias", root)
            for contact in contacts:
                if contact["alias"] == root:
                    target = contact["id"]

        if not target:
            raise kering.ConfigurationError(
                f"Invalid identifier '{root}' for {args.url}, not found"
            )

        # Build request parameters from arguments
        headers = {}
        for header in args.header:
            name, value = header.split(":", 1)
            headers[name.strip()] = value.strip()

        data = None
        if args.data:
            if args.data.startswith("@"):
                f = open(args.data[1:], "r")
                data = f.read()
            else:
                data = args.data.encode("utf-8")

        return_route = "/owl/response"

        # Parse query parameters into dictionary
        query_params = {}
        if parsed.query:
            parsed_params = parse_qs(parsed.query)
            query_params = {
                k: v[0] if len(v) == 1 else v for k, v in parsed_params.items()
            }

        client = AsyncClient(
            params=query_params,
            return_route=return_route,
            headers=list(headers.items()),
        )

        crypt_signer = CryptSigner(hby=hby, hab=hab, encryption_target=target)
        response = await client.request(
            crypt_signer=crypt_signer,
            url=args.url,
            json=args.json,
            files=None,  # TODO: support files from the commandline, maybe?
            data=data,
        )

        print(response.headers)
        print(await response.aread())
