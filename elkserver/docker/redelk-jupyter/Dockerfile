#
# Part of RedELK
#
# Jupyter notebooks for ad-hoc analysis of the RedELK indices and the BloodHound graph.
#
# The jupyter/* images on Docker Hub were frozen in October 2023; the project publishes to
# quay.io now, which is where this base image comes from.
#
# Authors:
# - Outflank B.V. / Marc Smeets
# - RedELK contributors
#

FROM quay.io/jupyter/scipy-notebook:2025-08-11

LABEL org.opencontainers.image.title="RedELK Jupyter Notebooks"
LABEL org.opencontainers.image.source="https://github.com/outflanknl/RedELK"

# The Elasticsearch client major must match the cluster (9.x), which is exactly the skew the old
# image had: it pinned elasticsearch==7.17.3 against a 7.17.9 cluster and would silently fail
# against anything newer.
RUN pip install --no-cache-dir \
        "elasticsearch>=9.0,<10" \
        "neo4j>=5.23,<6" \
        "pandas>=2.2,<3"

# Authentication is handled by the nginx reverse proxy in front of this container, which is why
# the notebook server itself runs tokenless; it is not published to the host.
CMD ["start-notebook.py", \
     "--IdentityProvider.token=", \
     "--ServerApp.password=", \
     "--ServerApp.allow_remote_access=True", \
     "--ServerApp.allow_origin=*", \
     "--ServerApp.base_url=/jupyter/"]
