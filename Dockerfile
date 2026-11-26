# Match the qualified node and panel sources.
FROM gozargah/marzban-node@sha256:f93791ee35aa98b3851b74e5556c33a1d4607caf3e10781f52f37add14ed974d AS node-source
ARG RIME_VERSION=0.9.3
ARG RIME_REVISION=development
LABEL org.opencontainers.image.source="https://github.com/MaksimSamarin/rime" \
      org.opencontainers.image.version=$RIME_VERSION \
      org.opencontainers.image.revision=$RIME_REVISION \
      org.opencontainers.image.licenses="AGPL-3.0 AND MPL-2.0" \
      org.rime.runtime.kind="node" \
      org.rime.management.auth="controller-mtls-v1" \
      org.rime.xray.version="26.6.1"
COPY scripts/vendor_xray.py /opt/rime-node-build/vendor_xray.py
RUN python /opt/rime-node-build/vendor_xray.py \
    && cp /opt/rime-xray/xray /usr/local/bin/xray
COPY node-runtime/ /opt/rime-node-build/
RUN python /opt/rime-node-build/apply.py /code

FROM gozargah/marzban@sha256:8e422c21997e5d2e3fa231eeff73c0a19193c20fc02fa4958e9368abb9623b8d
WORKDIR /code
ARG RIME_VERSION=0.9.3
ARG RIME_REVISION=development
LABEL org.opencontainers.image.source="https://github.com/MaksimSamarin/rime" \
      org.opencontainers.image.version=$RIME_VERSION \
      org.opencontainers.image.revision=$RIME_REVISION \
      org.opencontainers.image.licenses="AGPL-3.0 AND MPL-2.0 AND MIT"
# Remove the inherited frontend before copying the single Rime console.
RUN rm -rf /code/app/dashboard /code/build_dashboard.sh /code/marzban.code-workspace
COPY requirements.txt requirements-panel.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.txt -c requirements.lock
COPY . /code
RUN python /code/scripts/vendor_relay.py
COPY --from=node-source /code/rest_service.py /opt/rime-node-runtime/rest_service.py
COPY --from=node-source /code/node_autonomy.py /opt/rime-node-runtime/node_autonomy.py
COPY --from=node-source /code/api_bridge.py /opt/rime-node-runtime/api_bridge.py
COPY --from=node-source /opt/rime-xray/xray /opt/rime-probe/xray
COPY --from=node-source /opt/rime-xray/LICENSE.xray /opt/rime-probe/LICENSE.xray
COPY --from=node-source /opt/rime-xray/xray /opt/rime-hub/xray
COPY --from=node-source /opt/rime-xray/LICENSE.xray /opt/rime-hub/LICENSE.xray
# Public code must remain traversable when the runtime uses a non-root UID.
RUN find /code -type d -exec chmod 755 {} +
CMD ["bash", "-c", "alembic upgrade head && exec python main.py"]
