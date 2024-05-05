import configparser
import json
import logging
import os
import re
from typing import Annotated
import urllib.parse

from fastapi import FastAPI, Response, Header, status
import scitokens

app = FastAPI()
logger = logging.getLogger("uvicorn.error")


@app.get("/healthz")
def read_healthz():
    """Health check endpoint"""
    return "OK"


# @app.get("/auth", status_code=status.HTTP_202_ACCEPTED)
@app.get(
    "/auth",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        status.HTTP_401_UNAUTHORIZED: {},
        status.HTTP_403_FORBIDDEN: {},
    },
)
async def read_auth(
    response: Response,
    x_forwarded_uri: Annotated[str | None, Header()] = None,
    x_forwarded_method: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
):
    """Authorization check endpoint"""
    # Convert the operation to something that the token will know,
    # like read or write
    op = ""
    if x_forwarded_method == "GET":
        op = "read"
    elif x_forwarded_method in ["PUT", "POST", "DELETE", "MKCOL", "COPY", "MOVE"]:
        op = "write"

    # Convert the token to a SciToken (also check for errors with the token)
    if not authorization:
        # If we don't have an Authorization header, look for an authz query parameter
        parsed_uri = urllib.parse.urlparse(x_forwarded_uri)
        parsed_qs = urllib.parse.parse_qs(parsed_uri.query)
        try:
            authorization = parsed_qs["authz"][0]
        except KeyError:
            logger.info("No Authorization header presented")
            response.headers["WWW-Authenticate"] = 'Bearer realm="scitokens"'
            response.status_code = status.HTTP_401_UNAUTHORIZED
            return

    raw_token = authorization.removeprefix("Bearer ")

    # Convert the token
    # Send a 401 error code if there is any problem
    try:
        token = scitokens.SciToken.deserialize(raw_token, audience=g_global_audience)
    except Exception as e:
        logger.info("Invalid token: %s", str(e))
        response.headers[
            "WWW-Authenticate"
        ] = f'Bearer realm="scitokens",error="invalid_token",error_description="{str(e)}"'
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return

    # Pass the subject upstream as user
    if token.get("sub"):
        response.headers["X-Auth-Request-User"] = token.get("sub")

    (successful, message) = test_operation_path(op, x_forwarded_uri, token)
    if successful:
        logger.info(
            "Allowed %s for %s (%s) on %s",
            op,
            token.get("sub"),
            token.get("jti"),
            x_forwarded_uri,
        )
        response.status_code = status.HTTP_202_ACCEPTED
    else:
        logger.info(
            "Denied %s for %s (%s) on %s: %s",
            op,
            token.get("sub"),
            token.get("jti"),
            x_forwarded_uri,
            message,
        )
        response.status_code = status.HTTP_403_FORBIDDEN
    return


def test_operation_path(op, path, token):
    """
    Test whether an operation and path is allowed by this scitoken.

    :returns: (successful, message) true if the scitoken allows for this path & op, else false
    """
    # Setup a SciToken Enforcer
    try:
        issuer = token["iss"]
        base_path = g_authorized_issuers[issuer]["base_path"]
    except KeyError:
        return (False, "Issuer not in configuration")

    # The path above should consist of"
    # $base_path + / + $auth_path + / + $request_path = path
    if not path.startswith(base_path):
        return (False, "The requested path does not start with the base path")

    # Now remove the base path so we just get the auth_path + request_path
    if base_path == "/":
        auth_requested = path
    else:
        auth_requested = path.removeprefix(base_path)

    # Workaround for wlcg.ver=1.0 tokens
    if "wlcg.ver" in token._verified_claims:
        del token._verified_claims["wlcg.ver"]
        del token._verified_claims["client_id"]
        op = "storage." + op

    enforcer = scitokens.scitokens.Enforcer(token["iss"], audience=g_global_audience)
    try:
        if enforcer.test(token, op, auth_requested):
            return (True, "")
        return (False, enforcer.last_failure)
    except scitokens.scitokens.EnforcementError as e:
        return (False, str(e))


def config(fname):
    """Parse config file, matching xrootd-scitokens conventions"""
    authorized_issuers = {}
    logger.info("Trying to load configuration from %s", fname)
    cp = configparser.ConfigParser()
    cp.read(fname)
    for section in cp.sections():
        if not section.lower().startswith("issuer "):
            continue
        if "issuer" not in cp.options(section):
            logger.warning(
                "Ignoring section %s as it has no `issuer` option set.", section
            )
            continue
        if "base_path" not in cp.options(section):
            logger.warning(
                "Ignoring section %s as it has no `base_path` option set.", section
            )
            continue
        issuer = cp.get(section, "issuer")
        base_path = cp.get(section, "base_path")
        base_path = scitokens.urltools.normalize_path(base_path)
        issuer_info = authorized_issuers.setdefault(issuer, {})
        issuer_info["base_path"] = base_path
        if "map_subject" in cp.options(section):
            issuer_info["map_subject"] = cp.getboolean(section, "map_subject")
        logger.info(
            "Configured token access for %s (issuer %s): %s",
            section,
            issuer,
            str(issuer_info),
        )

    global_audience = ""
    if "audience_json" in cp.options("Global"):
        # Read in the audience as json.  Hopefully it's in list format or a string
        global_audience = json.loads(cp.get("Global", "audience_json"))
    elif "audience" in cp.options("Global"):
        global_audience = cp.get("Global", "audience")
        if "," in global_audience:
            # Split the audience list
            global_audience = re.split(r"\s*,\s*", global_audience)

    return authorized_issuers, global_audience


g_authorized_issuers, g_global_audience = config(
    os.environ.get("SCITOKENS_CONFIG", "/etc/scitokens/scitokens.cfg")
)
