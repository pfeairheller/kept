import json
import os
import logging
import re
from enum import Enum
from dataclasses import dataclass

from keri.core import parsing
from requests_toolbelt.multipart import decoder

from .essring import APIClient

DEFAULT_ROOT_AID = "ENKyfXRjsKXTLHRNjKDDzaG8ah6xe0-sw_pANmrqWTb1"
DEFAULT_API_AID = "EK5R4Y1mZXIjTJs-L4ljPrwbUu6uNWCJIjVIWhV6anUU"
DEFAULT_ROOT_OOBI = "http://127.0.0.1:5642/oobi/ENKyfXRjsKXTLHRNjKDDzaG8ah6xe0-sw_pANmrqWTb1/witness?name=healthKERI%20Root"
DEFAULT_API_OOBI = "http://127.0.0.1:5642/oobi/EK5R4Y1mZXIjTJs-L4ljPrwbUu6uNWCJIjVIWhV6anUU/witness?name=healthKERI%20API"
DEFAULT_UNPROTECTED_URL = "http://localhost:8989"
DEFAULT_PROTECTED_URL = "http://localhost:4443"
DEFAULT_REMOTE_UNPROTECTED_URL = "http://164.92.79.134:9696"
DEFAULT_REMOTE_PROTECTED_URL = "http://164.92.79.134:6969"

STAGING_ROOT_AID = "ENKyfXRjsKXTLHRNjKDDzaG8ah6xe0-sw_pANmrqWTb1"
STAGING_API_AID = "ELucL12aBcsSc90EbPOw_OpuSpizTb6pfqfA-WyiKFks"
STAGING_ROOT_OOBI = "http://127.0.0.1:5642/oobi/ENKyfXRjsKXTLHRNjKDDzaG8ah6xe0-sw_pANmrqWTb1/witness?name=healthKERI%20Root"
STAGING_API_OOBI = "http://127.0.0.1:5642/oobi/ELucL12aBcsSc90EbPOw_OpuSpizTb6pfqfA-WyiKFks/witness?name=healthKERI%20API"
STAGING_UNPROTECTED_URL = "http://localhost:8989"
STAGING_REMOTE_UNPROTECTED_URL = "http://164.92.79.134:9696"
STAGING_PROTECTED_URL = "http://localhost:8990"
STAGING_REMOTE_PROTECTED_URL = "http://164.92.79.134:6969"

PRODUCTION_ROOT_AID = "EO2ZPXThLo1GmRQ_fxFlDyQdzPGc9pEmxzeXIVLSFt3x"
PRODUCTION_API_AID = "ENJpJfLxehegdlxfzJj9qQHJDPDir3KJKsJWwqxCsTnb"
PRODUCTION_ROOT_OOBI = "https://root.healthkeri.net/oobi/EO2ZPXThLo1GmRQ_fxFlDyQdzPGc9pEmxzeXIVLSFt3x/witness?name=healthKERI%20Root"
PRODUCTION_API_OOBI = "https://root.healthkeri.net/oobi/ENJpJfLxehegdlxfzJj9qQHJDPDir3KJKsJWwqxCsTnb/witness?name=healthKERI%20API"
PRODUCTION_UNPROTECTED_URL = "https://api.healthkeri.net"
PRODUCTION_PROTECTED_URL = "http://64.225.88.24:5632"
PRODUCTION_REMOTE_UNPROTECTED_URL = PRODUCTION_UNPROTECTED_URL
PRODUCTION_REMOTE_PROTECTED_URL = PRODUCTION_PROTECTED_URL


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Environments(Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"


@dataclass
class HealthKERIConfig:
    _instance = None
    # The healthKERI identifiers to connect with
    root_aid: str = DEFAULT_ROOT_AID
    api_aid: str = DEFAULT_API_AID

    # OOBIS of healthKERI AIDs
    root_oobi: str = DEFAULT_ROOT_OOBI
    api_oobi: str = DEFAULT_API_OOBI

    # The healthKERI URLs to connect to
    unprotected_url: str = DEFAULT_UNPROTECTED_URL
    protected_url: str = DEFAULT_PROTECTED_URL

    # The environment the app is being run in.
    environment: Environments = Environments.PRODUCTION

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        environment = os.environ.get("ARCHIMEDES_ENVIRONMENT")
        match environment:
            case Environments.PRODUCTION.value:
                environment = Environments.PRODUCTION
            case Environments.STAGING.value:
                environment = Environments.STAGING
            case Environments.DEVELOPMENT.value:
                environment = Environments.DEVELOPMENT
            case _:
                environment = Environments.PRODUCTION
        logger.info(f"Running in the {environment} environment")

        # Set defaults for each environment, and default env is production
        root_aid = DEFAULT_ROOT_AID
        api_aid = DEFAULT_API_AID
        root_oobi = DEFAULT_ROOT_OOBI
        api_oobi = DEFAULT_API_OOBI
        unprotected_url = DEFAULT_UNPROTECTED_URL
        protected_url = DEFAULT_PROTECTED_URL
        remote_unprotected_url = DEFAULT_REMOTE_UNPROTECTED_URL
        remote_protected_url = DEFAULT_REMOTE_PROTECTED_URL

        match environment:
            case Environments.PRODUCTION:
                root_aid = PRODUCTION_ROOT_AID
                api_aid = PRODUCTION_API_AID
                root_oobi = PRODUCTION_ROOT_OOBI
                api_oobi = PRODUCTION_API_OOBI
                unprotected_url = PRODUCTION_UNPROTECTED_URL
                protected_url = PRODUCTION_PROTECTED_URL

            case Environments.STAGING:
                root_aid = STAGING_ROOT_AID
                api_aid = STAGING_API_AID
                root_oobi = STAGING_ROOT_OOBI
                api_oobi = STAGING_API_OOBI
                unprotected_url = STAGING_UNPROTECTED_URL
                protected_url = STAGING_PROTECTED_URL

            case Environments.DEVELOPMENT:
                root_aid = DEFAULT_ROOT_AID
                api_aid = DEFAULT_API_AID
                root_oobi = DEFAULT_ROOT_OOBI
                api_oobi = DEFAULT_API_OOBI
                unprotected_url = DEFAULT_UNPROTECTED_URL
                protected_url = DEFAULT_PROTECTED_URL

        # Environment variable overrides if available
        self.root_aid = os.environ.get("ARCHIMEDES_ROOT_AID", root_aid)
        self.api_aid = os.environ.get("ARCHIMEDES_API_AID", api_aid)
        self.root_oobi = os.environ.get("ARCHIMEDES_ROOT_OOBI", root_oobi)
        self.api_oobi = os.environ.get("ARCHIMEDES_API_OOBI", api_oobi)
        self.unprotected_url = os.environ.get(
            "ARCHIMEDES_UNPROTECTED_URL", unprotected_url
        )
        self.protected_url = os.environ.get("ARCHIMEDES_PROTECTED_URL", protected_url)
        self.remote_unprotected_url = os.environ.get(
            "ARCHIMEDES_REMOTE_UNPROTECTED_URL", remote_unprotected_url
        )
        self.remote_protected_url = os.environ.get(
            "ARCHIMEDES_REMOTE_PROTECTED_URL", remote_protected_url
        )
        self.environment = environment


async def fetch_netmap(config, hby, hab):
    essr = APIClient(url=config.protected_url, root=config.api_aid, hby=hby, hab=hab)

    response = await essr.request(
        path="/account/teams/netmap", method="GET", timeout=15
    )

    netmap = None
    if response.status_code == 200:
        logger.info(f"Fetched netmap using AID {hab.pre}")
        # Parse multipart response
        multipart_data = decoder.MultipartDecoder.from_response(response)

        for part in multipart_data.parts:
            name = get_part_name(part)

            if name == "netmap":
                # Parse JSON netmap
                netmap_data = part.content.decode("utf-8")
                netmap = json.loads(netmap_data)
                logger.info("Parsed netmap")

            else:
                # Parse CESR stream with KERI
                aid = name
                kels_data = part.content

                if aid not in hby.kevers:
                    parsing.Parser(kvy=hby.kvy, rvy=hby.rvy, local=False).parse(
                        ims=kels_data
                    )
                    hby.kvy.processEscrows()
                    logger.info(f"Parsed CESR stream for {aid}")

    added_members = []
    added_servers = []
    if netmap:
        members = netmap.get("members", [])
        for member in members:
            aid = member["aid"]
            if aid in hby.kevers:
                added_members.append(member)

        servers = netmap.get("servers", [])
        for server in servers:
            aid = server["aid"]
            if aid in hby.kevers:
                added_servers.append(server)

    return added_members, added_servers


def get_part_name(part):
    content_disposition = part.headers.get(b"Content-Disposition", b"").decode("utf-8")
    match = re.search(r'name="([^"]+)"', content_disposition)
    return match.group(1) if match else None
