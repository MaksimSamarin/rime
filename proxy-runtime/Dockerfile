FROM ubuntu@sha256:78d4744ead1f5b19b04d0df558ab182a5300903900755e515b2ca4d10eb2044d
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends squid-openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/squid /var/spool/squid \
    && chown -R 65534:65534 /run/squid /var/spool/squid
USER 65534:65534
ENTRYPOINT ["/usr/sbin/squid", "-N", "-d", "1", "-f", "/state/squid.conf"]
