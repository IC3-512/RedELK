#
# Part of RedELK
#
# The RedELK base image: the scheduler that runs the alarm, enrichment and C2 connector modules,
# provisions Elasticsearch and Kibana, and pulls artefacts off the C2 servers.
#
# It used to be built on phusion/baseimage:18.04 (Ubuntu 18.04, Python 3.6, last built in 2020),
# which is what pinned the Elasticsearch client - and therefore the whole stack - to 7.x.
#
# Authors:
# - Outflank B.V. / Marc Smeets
# - Lorenzo Bernardi (@fastlorenzo)
# - RedELK contributors
#

FROM python:3.13-slim-bookworm

LABEL org.opencontainers.image.title="RedELK Base"
LABEL org.opencontainers.image.description="RedELK alarm, enrichment and C2 connector runtime"
LABEL org.opencontainers.image.source="https://github.com/IC3-512/RedELK"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    REDELK_HOME=/usr/share/redelk

# cron runs the scheduler; rsync + openssh-client pull C2 artefacts; tini reaps the processes
# cron leaves behind.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        cron \
        openssh-client \
        rsync \
        tini \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 --shell /bin/sh redelk \
    && mkdir -p /var/log/redelk /var/www/html/c2logs /var/lib/redelk /etc/redelk \
    && chown -R redelk:redelk /var/log/redelk /var/www/html/c2logs /var/lib/redelk

COPY ./redelkinstalldata/scripts/requirements.txt ${REDELK_HOME}/bin/requirements.txt
RUN pip install --no-cache-dir -r ${REDELK_HOME}/bin/requirements.txt

COPY --chown=redelk:redelk ./redelkinstalldata/scripts/ ${REDELK_HOME}/bin/
COPY --chown=redelk:redelk ./redelkinstalldata/templates/ /opt/redelk/templates/
COPY --chown=redelk:redelk ./redelkinstalldata/kibana/ /opt/redelk/kibana/
COPY --chown=redelk:redelk ./redelkinstalldata/data/ /opt/redelk/data/

RUN chmod -R 0755 ${REDELK_HOME}/bin

WORKDIR ${REDELK_HOME}/bin

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=20 \
    CMD test -f /var/lib/redelk/es-provisioned || exit 1

# tini as PID 1 so cron's children are reaped and SIGTERM reaches the container cleanly.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "/usr/share/redelk/bin/entrypoint.py"]
