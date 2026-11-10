FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f AS certificates

FROM --platform=$BUILDPLATFORM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS package
COPY --from=certificates /etc/ssl/cert.pem /etc/ssl/certs/ca-certificates.crt
RUN sed -i 's#http://deb.debian.org#https://deb.debian.org#' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=3 update \
    && apt-get -o Acquire::Retries=3 install -y --no-install-recommends python3 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
ARG TOPSAP_PUBLIC_PROXY=0
COPY scripts/upstream.py scripts/public_proxy.py packages.lock.json /build/
RUN case "$TOPSAP_PUBLIC_PROXY" in 1) set -- --public-proxy;; 0) set --;; *) exit 1;; esac \
    && python3 /build/upstream.py download --arch "$TARGETARCH" --lock /build/packages.lock.json --output /tmp/topsap.deb "$@" \
    && test "$(dpkg-deb -f /tmp/topsap.deb Package)" = cn.com.topvpn \
    && test "$(dpkg-deb -f /tmp/topsap.deb Architecture)" = "$TARGETARCH" \
    && test "$(dpkg-deb -f /tmp/topsap.deb Version)" = "$(python3 -c 'import json,sys; print(json.load(open("/build/packages.lock.json"))["packages"][sys.argv[1]]["version"])' "$TARGETARCH")" \
    && mkdir -p /payload \
    && dpkg-deb -x /tmp/topsap.deb /tmp/payload \
    && cp -a /tmp/payload/opt/apps/cn.com.topvpn /payload/ \
    && chmod -R go-w,a-s /payload/cn.com.topvpn \
    && chmod 0755 /payload/cn.com.topvpn/files/sv_websrv /payload/cn.com.topvpn/files/ele/TopSAP \
    && rm -rf /tmp/topsap.deb /tmp/payload


FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/tmp/topsap-home \
    DISPLAY=:0 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

COPY --from=certificates /etc/ssl/cert.pem /etc/ssl/certs/ca-certificates.crt

RUN printf '%s\n' \
      'Acquire::Retries "3";' \
      'Acquire::ForceIPv4 "true";' \
      'Acquire::http::Timeout "30";' \
      'Acquire::https::Timeout "30";' \
      > /etc/apt/apt.conf.d/80-retry \
    && sed -i 's#http://deb.debian.org#https://deb.debian.org#' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      iproute2 \
      iptables \
      microsocks \
      util-linux \
      iputils-ping \
      libasound2 \
      libatk-bridge2.0-0 \
      libatk1.0-0 \
      libatspi2.0-0 \
      libc6 \
      libcairo2 \
      libcups2 \
      libdbus-1-3 \
      libdrm2 \
      libexpat1 \
      libfontconfig1 \
      libgbm1 \
      libgcc-s1 \
      libglib2.0-0 \
      libgtk-3-0 \
      libnspr4 \
      libnss3 \
      libpango-1.0-0 \
      libpangocairo-1.0-0 \
      libstdc++6 \
      libudev1 \
      libx11-xcb1 \
      libxcomposite1 \
      libxcursor1 \
      libxdamage1 \
      libxfixes3 \
      libxi6 \
      libxkbcommon0 \
      libxrandr2 \
      libxrender1 \
      libxshmfence1 \
      libxss1 \
      libxtst6 \
      libusb-1.0-0 \
      libuuid1 \
      novnc \
      openbox \
      python3 \
      python3-websocket \
      websockify \
      x11vnc \
      xvfb \
    && rm -rf /var/lib/apt/lists/*

COPY --from=package /payload/ /usr/local/lib/topsap-payload/

COPY app/ /usr/local/lib/topsap-service/
COPY sudo /usr/local/bin/sudo
RUN chmod 0755 /usr/local/bin/sudo
LABEL org.opencontainers.image.title="TopSAP VPN SOCKS5 service" \
      org.opencontainers.image.source="https://github.com/KaranocaVe/topsap-vpn-docker"
EXPOSE 1080
ENTRYPOINT ["python3", "/usr/local/lib/topsap-service/service.py"]
