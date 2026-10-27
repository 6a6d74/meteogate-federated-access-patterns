# A member gateway: APISIX with the federation's plugin and the operator-YAML generator.
#
# Build from the repository root, so the image uses the data plane's own generator and
# plugin rather than copies of them:
#
#   docker build -f member-gateway/Dockerfile -t member-gateway .
#
# At start it generates APISIX's configuration from /config/gateway.yaml and the
# environment, then runs APISIX. `routes`, `info` and `check` run the helpers instead.
# Python for the generator and the helpers. The APISIX image is Debian 11, whose package
# mirrors no longer serve it, so rather than apt-get, take a Python built for the same
# Debian release from the official image, with PyYAML at the version the testbed uses.
FROM python:3.12.11-slim-bullseye AS python
RUN pip install --no-cache-dir "pyyaml==6.0.3" \
 && rm -rf /usr/local/lib/python3.12/test /usr/local/lib/python3.12/ensurepip

FROM apache/apisix:3.13.0-debian

USER root
COPY --from=python /usr/local/bin/python3.12 /usr/local/bin/python3.12
COPY --from=python /usr/local/lib/libpython3.12.so.1.0 /usr/local/lib/
COPY --from=python /usr/local/lib/python3.12/ /usr/local/lib/python3.12/
RUN ln -s python3.12 /usr/local/bin/python3 && ldconfig && python3 -c "import yaml, ssl"

COPY member-gateway/apisix/config.yaml /usr/local/apisix/conf/config.yaml
COPY data-plane/apisix/plugins/ /opt/apisix/plugins/
COPY data-plane/scripts/gen-apisix-config.py /opt/member-gateway/gen-apisix-config.py
COPY member-gateway/scripts/ /opt/member-gateway/
COPY member-gateway/entrypoint.sh /opt/member-gateway/entrypoint.sh
# Readable whoever built it: a builder's umask (077 on some Macs) carries into COPY.
RUN chmod a+r /usr/local/apisix/conf/config.yaml \
 && chmod -R a+rX /opt/apisix/plugins /opt/member-gateway \
 && chmod a+x /opt/member-gateway/*.py /opt/member-gateway/entrypoint.sh

USER apisix
ENV APISIX_STAND_ALONE=true
EXPOSE 9080 9443
# /status, not /status/ready: in file mode APISIX 3.13 only marks a worker ready when
# apisix.yaml changes after start, and here it is written before. Nothing is lost —
# the file exists before APISIX starts, and it is read before anything is served.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s \
  CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7085/status', timeout=2)"]
ENTRYPOINT ["/opt/member-gateway/entrypoint.sh"]
CMD ["serve"]
