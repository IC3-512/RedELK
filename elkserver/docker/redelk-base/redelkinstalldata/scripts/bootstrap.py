#!/usr/bin/env python3
"""
Part of RedELK

Provisioning of Elasticsearch and Kibana.

Replaces 42_redelk-base-docker-init.sh, which drove the same API calls with curl and checked
them with `ERROR=$?`. curl exits 0 for HTTP 400, 401 and 500, so that script reported success no
matter what happened - a whole class of "RedELK installed fine but nothing works" reports.

Everything here is idempotent. The Elasticsearch half runs on every container start (users,
roles, ILM policy and index templates must match the running configuration). The Kibana half
imports saved objects only once, so that dashboards an operator customised are not silently
reverted on every restart; force it with REDELK_FORCE_KIBANA_IMPORT=1.

Authors:
- Outflank B.V. / Marc Smeets
- RedELK contributors
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests
import urllib3

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=os.environ.get("REDELK_LOGLEVEL", "INFO"))
logger = logging.getLogger("bootstrap")

ES_URL = os.environ.get("ES_URL", "https://redelk-elasticsearch:9200").rstrip("/")
KIBANA_URL = os.environ.get("KIBANA_URL", "https://redelk-kibana:5601").rstrip("/")
CA_PATH = os.environ.get("REDELK_CA", "/etc/redelk/certs/ca/ca.crt")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "")

TEMPLATE_DIR = Path("/opt/redelk/templates")
KIBANA_ASSET_DIR = Path("/opt/redelk/kibana")
STATE_DIR = Path("/var/lib/redelk")
ES_MARKER = STATE_DIR / "es-provisioned"
KIBANA_MARKER = STATE_DIR / "kibana-provisioned"

TIMEOUT = 30
WAIT_INTERVAL = 5
WAIT_TIMEOUT = int(os.environ.get("REDELK_WAIT_TIMEOUT", "900"))

# Kibana answers 503 for a while after it calls itself available: `overall.level` flips before the
# `licensing` plugin has fetched the license, and the security plugin cannot authenticate anything
# until it has. On a real deployment that window was 4.8 seconds wide and the first import request
# landed 33 milliseconds inside it - which ended provisioning permanently and left `redelkctl
# install` polling 600 seconds for an import that had already given up. The import itself takes
# 7.6 seconds, so nothing here was ever slow; it was a race, which is why it never correlated
# with the CPU the node was given.
TRANSIENT_STATUS = (502, 503, 504)
RETRY_TIMEOUT = 120
RETRY_INTERVAL = 5

# Indices RedELK writes. The ingest role is scoped to exactly these - the previous role also
# granted access to auditbeat*, packetbeat*, apm* and friends that RedELK never uses.
# Indices the daemon writes to by name rather than through Logstash, so nothing else guarantees
# they exist before the first document arrives. create_managed_indices() makes them, which is the
# only way their index template gets a say in the mapping - see the note there.
MANAGED_INDICES = ["redelk-modules"]

REDELK_INDICES = [
    "rtops-*",
    "redirtraffic-*",
    "credentials-*",
    "bluecheck-*",
    "email-*",
    "implantsdb",
    "redelk-*",
]


class ProvisioningError(Exception):
    """A provisioning step failed in a way that needs a human."""


def _session(verify: str | bool) -> requests.Session:
    session = requests.Session()
    session.verify = verify
    session.auth = ("elastic", ELASTIC_PASSWORD)
    return session


def _verify_target() -> str | bool:
    if Path(CA_PATH).is_file():
        return CA_PATH
    # Falling back to no verification is bad, but failing to provision at all is worse; make the
    # trade-off loud instead of silent (the old script passed -k unconditionally).
    logger.warning(
        "CA certificate %s not found - falling back to unverified TLS for provisioning", CA_PATH
    )
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return False


def request(
    session: requests.Session,
    method: str,
    url: str,
    *,
    expect: tuple[int, ...] = (200, 201),
    description: str = "",
    **kwargs: Any,
) -> requests.Response:
    """Make a request and fail loudly on an unexpected HTTP status.

    A transport failure or 502/503/504 is retried instead of raised. Neither means "this request is
    wrong"; during provisioning they normally mean that Elasticsearch or Kibana is up but still
    settling. Treating a read timeout as fatal left the base container alive but permanently
    unprovisioned on a real two-vCPU deployment.

    Because of that, any body passed in `files` or `data` has to be replayable: bytes, not an open
    file handle, which a retry would resend as an empty body.
    """
    kwargs.setdefault("timeout", TIMEOUT)
    label = description or f"{method} {url}"
    deadline = time.monotonic() + RETRY_TIMEOUT
    while True:
        try:
            response = session.request(method, url, **kwargs)
        except requests.RequestException as error:
            if time.monotonic() >= deadline:
                raise ProvisioningError(
                    f"{label} failed after transient transport errors: "
                    f"{type(error).__name__}: {error}"
                ) from error
            logger.info(
                "%s: %s, retrying in %ss",
                label,
                type(error).__name__,
                RETRY_INTERVAL,
            )
            time.sleep(RETRY_INTERVAL)
            continue
        if response.status_code in expect:
            return response
        if response.status_code not in TRANSIENT_STATUS or time.monotonic() >= deadline:
            raise ProvisioningError(
                f"{label} failed: HTTP {response.status_code} {response.text[:500]}"
            )
        logger.info("%s: HTTP %s, retrying in %ss", label, response.status_code, RETRY_INTERVAL)
        time.sleep(RETRY_INTERVAL)


def wait_for(
    session: requests.Session, url: str, label: str, check, headers: dict | None = None
) -> None:
    deadline = time.monotonic() + WAIT_TIMEOUT
    last_error = ""
    while time.monotonic() < deadline:
        try:
            response = session.get(url, timeout=10, headers=headers)
            if check(response):
                logger.info("%s is up", label)
                return
            last_error = f"HTTP {response.status_code}: {response.text[:200]}"
        except requests.RequestException as error:
            last_error = str(error)
        logger.debug("waiting for %s (%s)", label, last_error)
        time.sleep(WAIT_INTERVAL)
    raise ProvisioningError(
        f"{label} did not become available within {WAIT_TIMEOUT}s: {last_error}"
    )


# --------------------------------------------------------------------------------------------
# Elasticsearch
# --------------------------------------------------------------------------------------------


def provision_elasticsearch(session: requests.Session) -> None:
    wait_for(
        session,
        f"{ES_URL}/_cluster/health?wait_for_status=yellow&timeout=10s",
        "Elasticsearch",
        lambda response: (
            response.status_code == 200 and response.json().get("status") in ("green", "yellow")
        ),
    )

    set_builtin_passwords(session)
    create_roles(session)
    create_users(session)
    install_ilm_policy(session)
    install_templates(session)
    create_managed_indices(session)

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    ES_MARKER.write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), encoding="utf-8")
    logger.info("Elasticsearch provisioning complete")


def set_builtin_passwords(session: requests.Session) -> None:
    for user, variable in (
        ("kibana_system", "CREDS_kibana_system"),
        ("logstash_system", "CREDS_logstash_system"),
    ):
        password = os.environ.get(variable, "")
        if not password:
            logger.warning("%s is not set; skipping the %s password", variable, user)
            continue
        request(
            session,
            "POST",
            f"{ES_URL}/_security/user/{user}/_password",
            json={"password": password},
            description=f"setting the {user} password",
        )
        logger.info("password set for %s", user)


def create_roles(session: requests.Session) -> None:
    roles = {
        "redelk_ingest": {
            "cluster": ["monitor", "manage_ilm", "manage_index_templates"],
            "indices": [
                {
                    "names": REDELK_INDICES,
                    "privileges": [
                        "create_index",
                        "create_doc",
                        "index",
                        "write",
                        "read",
                        "view_index_metadata",
                        "manage",
                    ],
                }
            ],
        },
        # The operator account an analyst logs into Kibana with. It can read and annotate the
        # RedELK data (alarms write tags back into the documents) but it is deliberately not a
        # superuser, which is what the previous installer made it.
        "redelk_operator": {
            "cluster": ["monitor"],
            "indices": [
                {
                    "names": REDELK_INDICES,
                    "privileges": [
                        "read",
                        "write",
                        "view_index_metadata",
                        "maintenance",
                        # Kibana resolves ES|QL views while working out a data view's time field,
                        # which happens on Discover and on every dashboard load. Without this the
                        # operator's own UI answers 500, with
                        # "action [indices:admin/esql/view/get] is unauthorized for user [redelk]"
                        # in the Kibana log - so the account RedELK exists to be used from cannot
                        # use it.
                        #
                        # Granted as the action rather than a named privilege because 9.5 has no
                        # index privilege that covers it: `GET _security/privilege/_builtin` lists
                        # 32 index privileges and none mentions esql, the only esql entry being the
                        # CLUSTER privilege monitor_esql - which was tested against a real 9.5.0
                        # and still returns 403. `manage` does grant it, and also grants deleting
                        # and reconfiguring every index the role can see, which is not something
                        # to hand an analyst account to fix a read path.
                        "indices:admin/esql/view/*",
                        # `write` covers indexing a document but not bringing the index into
                        # existence, and RedELK writes to date-stamped indices - so the first
                        # write of each day is to an index that does not exist yet and fails
                        # with "action [indices:admin/auto_create] is unauthorized". The
                        # operator command log hits this on its first session after midnight.
                        #
                        # auto_configure, not create_index: both let the bulk through (checked
                        # against 9.5.0 - 403 without either, 201 with either), and this one is
                        # exactly "may auto-create and update mappings" without also granting
                        # deliberate index creation.
                        "auto_configure",
                    ],
                }
            ],
            "applications": [
                {"application": "kibana-.kibana", "privileges": ["all"], "resources": ["*"]}
            ],
        },
    }
    for name, body in roles.items():
        request(
            session,
            "PUT",
            f"{ES_URL}/_security/role/{name}",
            json=body,
            description=f"creating the {name} role",
        )
        logger.info("role %s installed", name)


def create_users(session: requests.Session) -> None:
    users = {
        "redelk_ingest": {
            "password": os.environ.get("CREDS_redelk_ingest", ""),
            "roles": ["redelk_ingest"],
            "full_name": "RedELK ingest (Logstash)",
        },
        "redelk": {
            "password": os.environ.get("CREDS_redelk", ""),
            "roles": ["redelk_operator", "kibana_admin"],
            "full_name": "RedELK operator",
        },
    }
    for name, body in users.items():
        if not body["password"]:
            logger.warning("no password configured for %s; skipping", name)
            continue
        request(
            session,
            "PUT",
            f"{ES_URL}/_security/user/{name}",
            json=body,
            description=f"creating the {name} user",
        )
        logger.info("user %s installed", name)


def install_ilm_policy(session: requests.Session) -> None:
    path = TEMPLATE_DIR / "redelk_elasticsearch_ilm.json"
    if not path.is_file():
        raise ProvisioningError(f"{path} is missing from the image")
    request(
        session,
        "PUT",
        f"{ES_URL}/_ilm/policy/redelk",
        json=json.loads(path.read_text(encoding="utf-8")),
        description="installing the redelk ILM policy",
    )
    logger.info("ILM policy installed")


def create_managed_indices(session: requests.Session) -> None:
    """Create the indices the daemon writes to, so their template decides the mapping.

    es.index() creates a missing index on the spot, with whatever mapping Elasticsearch infers from
    the first document - and a field's mapping is fixed at creation. So the first of two things to
    happen decides it: this function, or the daemon's first write.

    Losing that race is silent and permanent. Measured on a live deployment, redelk-modules was
    created at 12:06:47, before provisioning ever reached the templates, so module.name and
    module.type were inferred as `text`. Nine panels of the Health dashboard aggregate on those
    fields, and every one answered

        Fielddata is disabled on [module.name] in [redelk-modules]

    instead of rendering - the dashboard an operator opens to find out whether their stack is
    working was the one dashboard that did not work. Installing the template afterwards fixes
    nothing, because a template is only consulted when an index is created.

    Creating the index here is idempotent: 400 resource_already_exists_exception is the expected
    answer on every start after the first.
    """
    for index in MANAGED_INDICES:
        response = session.head(f"{ES_URL}/{index}", timeout=TIMEOUT)
        if response.status_code == 200:
            continue
        request(
            session,
            "PUT",
            f"{ES_URL}/{index}",
            expect=(200, 400),
            description=f"creating index {index}",
        )
        logger.info("index %s created from its template", index)


def install_templates(session: requests.Session) -> None:
    """Install component templates first, then the index templates that compose them."""
    component_dir = TEMPLATE_DIR / "component"
    if component_dir.is_dir():
        for path in sorted(component_dir.glob("*.json")):
            name = path.stem
            request(
                session,
                "PUT",
                f"{ES_URL}/_component_template/{name}",
                json=json.loads(path.read_text(encoding="utf-8")),
                description=f"installing component template {name}",
            )
            logger.info("component template %s installed", name)

    installed = 0
    for path in sorted(TEMPLATE_DIR.glob("redelk_elasticsearch_template_*.json")):
        name = "redelk-" + path.stem.replace("redelk_elasticsearch_template_", "")
        body = json.loads(path.read_text(encoding="utf-8"))
        if "index_patterns" not in body:
            raise ProvisioningError(
                f"{path} is not a composable index template (no index_patterns); "
                "RedELK v3 no longer installs legacy _template documents"
            )
        request(
            session,
            "PUT",
            f"{ES_URL}/_index_template/{name}",
            json=body,
            description=f"installing index template {name}",
        )
        installed += 1
        logger.info("index template %s installed", name)

    if not installed:
        raise ProvisioningError(f"no index templates found in {TEMPLATE_DIR}")


# --------------------------------------------------------------------------------------------
# Kibana
# --------------------------------------------------------------------------------------------


def provision_kibana(session: requests.Session) -> None:
    if KIBANA_MARKER.is_file() and os.environ.get("REDELK_FORCE_KIBANA_IMPORT") != "1":
        logger.info(
            "Kibana saved objects were already imported; set REDELK_FORCE_KIBANA_IMPORT=1 to "
            "re-import them (this overwrites operator changes)"
        )
        return

    # Kibana 9 gates several of these routes behind the internal-origin header; without it
    # /api/kibana/settings answers "exists but is not available with the current configuration".
    headers = {"kbn-xsrf": "true", "x-elastic-internal-origin": "Kibana"}

    # Deliberately not /api/status. That route is unauthenticated and reports `overall: available`
    # while `plugins.licensing` is still starting, so it proves neither that the credentials work
    # nor that a saved-objects call will be answered - and waiting on it opened the gate 33
    # milliseconds before the first import was refused with a 503.
    #
    # Polling the API this function is about to use is readiness by definition rather than by
    # proxy: a 200 here means authentication, the license and the saved-objects service are all
    # live, whichever of them happens to be slowest today.
    wait_for(
        session,
        f"{KIBANA_URL}/api/saved_objects/_find?type=dashboard&per_page=1",
        "Kibana",
        lambda response: response.status_code == 200,
        headers=headers,
    )

    # Data views must exist before the searches and dashboards that reference them, which is why
    # the files carry a numeric prefix (redelk_kibana_01_dataviews.ndjson, 02_searches, ...).
    # Sorting by name is therefore the import order.
    files = sorted(TEMPLATE_DIR.glob("redelk_kibana_*.ndjson"), key=lambda path: path.name)
    for path in files:
        if path.stat().st_size == 0:
            logger.warning("skipping empty saved-object file %s", path.name)
            continue
        # Read the bytes rather than handing `request` an open handle: it retries a 503, and a
        # retry would resend a handle that the first attempt already consumed - an empty import
        # that reports success and silently installs nothing.
        response = request(
            session,
            "POST",
            f"{KIBANA_URL}/api/saved_objects/_import",
            params={"overwrite": "true"},
            headers=headers,
            files={"file": (path.name, path.read_bytes(), "application/ndjson")},
            description=f"importing {path.name}",
        )
        document = response.json()
        if not document.get("success"):
            errors = json.dumps(document.get("errors", []))[:1000]
            raise ProvisioningError(f"importing {path.name} reported errors: {errors}")
        logger.info("imported %s (%s objects)", path.name, document.get("successCount", 0))

    apply_settings(session, headers)
    apply_space_branding(session, headers)

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    KIBANA_MARKER.write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), encoding="utf-8")
    logger.info("Kibana provisioning complete")


def apply_settings(session: requests.Session, headers: dict[str, str]) -> None:
    path = TEMPLATE_DIR / "redelk_kibana_settings.json"
    if not path.is_file():
        logger.info("no Kibana advanced settings to apply")
        return
    request(
        session,
        "POST",
        f"{KIBANA_URL}/api/kibana/settings",
        headers=headers,
        json=json.loads(path.read_text(encoding="utf-8")),
        description="applying Kibana advanced settings",
    )
    logger.info("Kibana advanced settings applied")


def apply_space_branding(session: requests.Session, headers: dict[str, str]) -> None:
    path = KIBANA_ASSET_DIR / "redelklogo.json"
    if not path.is_file():
        return
    try:
        request(
            session,
            "PUT",
            f"{KIBANA_URL}/api/spaces/space/default",
            headers=headers,
            json=json.loads(path.read_text(encoding="utf-8")),
            description="setting the RedELK space logo",
        )
        logger.info("space branding applied")
    except ProvisioningError as error:
        # Cosmetic only - never let it block provisioning.
        logger.warning("could not apply the space logo: %s", error)


# --------------------------------------------------------------------------------------------


def main() -> int:
    if not ELASTIC_PASSWORD:
        logger.error("ELASTIC_PASSWORD is not set; cannot provision")
        return 1

    verify = _verify_target()
    session = _session(verify)

    try:
        provision_elasticsearch(session)
    except ProvisioningError as error:
        logger.error("Elasticsearch provisioning failed: %s", error)
        return 1

    try:
        provision_kibana(session)
    except ProvisioningError as error:
        # Elasticsearch is provisioned at this point, so ingestion works even if the dashboards
        # did not import. Report it clearly rather than pretending everything is fine.
        logger.error("Kibana provisioning failed: %s", error)
        logger.error("Ingestion will still work. Re-run with: docker compose restart base")
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
