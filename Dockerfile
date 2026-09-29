# Packages the prebuilt static (musl) binaries produced by the release workflow.
# Expected build context layout:
#   dist/amd64/porkbun_ddns
#   dist/arm64/porkbun_ddns
FROM alpine:3

ARG TARGETARCH

COPY --chmod=755 dist/${TARGETARCH}/porkbun_ddns /usr/local/bin/porkbun_ddns

# Configuration and logs are stored in /data when running inside Docker
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/porkbun_ddns"]
