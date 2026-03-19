import asyncio

import click
from kept.core.authentication import CryptSigner
from kept.core.tcp.server import KERITCPServer
from kept.essr.server import JSONResponse, Mount, PlainTextResponse, Rack, Request
from keri.app.cli.common import existing


async def handle_mcp(scope, receive, send):
    response = PlainTextResponse("Hello, world!")
    await response(scope, receive, send)


async def handle_other_stuff(scope, receive, send):
    req = Request(scope, receive)
    print(await req.body())

    response = JSONResponse(dict(msg="This is the other stuff!"))
    await response(scope, receive, send)


@click.command()
@click.option("--port", default=8000, help="Port to listen on for ESSR")
@click.option("--name", default="rack", help="Database environment name")
@click.option(
    "--alias",
    default="rack",
    help="Identifier alias or AID to use to decrypt messages and sign responses",
)
def main(port: int, name: str, alias: str) -> int:

    with existing.existingHab(name=name, alias=alias) as (hby, hab):
        sign_crypter = CryptSigner(hby, hab)

        app = Rack(
            hby=hby,
            crypt_signer=sign_crypter,
            routes=[
                Mount(path="/mcp", app=handle_mcp),
                Mount(path="/other/stuff", app=handle_other_stuff),
            ],
        )

        server = KERITCPServer(app=app, port=port)

        asyncio.run(server.start())

    return 0
