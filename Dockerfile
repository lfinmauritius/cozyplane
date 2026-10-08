# syntax=docker/dockerfile:1

# Build the cozyplane agent and CNI plugin. The compiled eBPF object is
# committed and embedded via go:embed, so no clang is needed here.
# Pin the builder to the native build platform and cross-compile via GOARCH;
# otherwise buildx runs the toolchain under QEMU for the arm64 leg (glacial).
# Bases are digest-pinned for digest-reproducible releases (#4): a floating tag
# resolving to a new base silently changes every layer above it. Bump the pins
# deliberately.
FROM --platform=$BUILDPLATFORM golang:1.26.8-bookworm@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETARCH=amd64
# -buildvcs=false: VCS stamping embeds the commit hash, so two commits with
# identical sources produced different binaries — exactly what defeats the
# digest-pin loop (#4): the pin commit itself changed the digest it pinned.
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-agent ./cmd/agent && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane ./cmd/cni && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/sdn-controller ./cmd/sdn-controller && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-apiserver ./cmd/apiserver && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-gateway ./cmd/gateway && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-vpn-gateway ./cmd/vpn-gateway && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-vpn-gateway-ipsec ./cmd/vpn-gateway-ipsec && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-vpn-routing ./cmd/vpn-routing && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-responder ./cmd/responder && \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -o /out/cozyplane-flowctl ./cmd/flowctl

# Fetch the upstream host-local and loopback CNI plugins.
FROM --platform=$BUILDPLATFORM curlimages/curl:8.11.0@sha256:83a505ba2ba62f208ed6e410c268b7b9aa48f0f7b403c8108b9773b44199dbba AS cni
ARG TARGETARCH=amd64
ARG CNI_PLUGINS_VERSION=v1.9.1
RUN case "${CNI_PLUGINS_VERSION}/${TARGETARCH}" in \
      v1.9.1/amd64) checksum=b98f74a0f8522f0a83867178729c1aa70f2158f90c45a2ca8fa791db1c76b303 ;; \
      v1.9.1/arm64) checksum=56171987d3947707c3563db2f4001bccaf50fd63468611b9f3cbecb1375ee7ec ;; \
      *) printf 'No trusted CNI checksum for %s/%s\n' "${CNI_PLUGINS_VERSION}" "${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSL --proto '=https' -o /tmp/cni.tgz \
      https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${TARGETARCH}-${CNI_PLUGINS_VERSION}.tgz && \
    printf '%s  /tmp/cni.tgz\n' "${checksum}" | sha256sum -c - && \
    mkdir -p /tmp/cni/bin && \
    tar -xzf /tmp/cni.tgz -C /tmp/cni/bin ./host-local ./loopback

FROM debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
# iptables (nft backend) for the conditional FORWARD ACCEPT rule and the legacy
# --masquerade=iptables mode; the init container shells out to `cp` to install
# plugins. wget is the operator's read path for the loopback-only flow endpoint
# (docs/observability.md §4): cozyplane-flowctl exec's `wget` in this container
# to reach 127.0.0.1:9412, so it must be present. Timestamped apt byproducts
# (logs, caches) are removed in the same layer so the layer content is
# reproducible (#4); file mtimes are normalized by the release rewrite-timestamp.
# strongswan + strongswan-swanctl provide charon and its VICI plugin — the IPsec
# backend of the managed VPN appliance (issue #6, cmd/vpn-gateway-ipsec) runs
# charon directly and drives it over VICI. Only the appliance pod uses them; the
# agent/gateway/apiserver never load charon.
RUN apt-get update && apt-get install -y --no-install-recommends iptables wget strongswan strongswan-swanctl libcharon-extra-plugins libcharon-extauth-plugins frr && \
    rm -rf /var/lib/apt/lists/* /var/log/dpkg.log /var/log/apt \
           /var/log/alternatives.log /var/cache/ldconfig/aux-cache
COPY --from=build /out/cozyplane-agent /usr/local/bin/cozyplane-agent
COPY --from=build /out/sdn-controller /usr/local/bin/sdn-controller
COPY --from=build /out/cozyplane-apiserver /usr/local/bin/cozyplane-apiserver
COPY --from=build /out/cozyplane-gateway /usr/local/bin/cozyplane-gateway
COPY --from=build /out/cozyplane-vpn-gateway /usr/local/bin/cozyplane-vpn-gateway
COPY --from=build /out/cozyplane-vpn-gateway-ipsec /usr/local/bin/cozyplane-vpn-gateway-ipsec
COPY --from=build /out/cozyplane-vpn-routing /usr/local/bin/cozyplane-vpn-routing
COPY --from=build /out/cozyplane-responder /usr/local/bin/cozyplane-responder
COPY --from=build /out/cozyplane-flowctl /usr/local/bin/cozyplane-flowctl
COPY --from=build /out/cozyplane /opt/cni/bin/cozyplane
COPY --from=cni /tmp/cni/bin/host-local /opt/cni/bin/host-local
COPY --from=cni /tmp/cni/bin/loopback /opt/cni/bin/loopback
ENTRYPOINT ["/usr/local/bin/cozyplane-agent"]
