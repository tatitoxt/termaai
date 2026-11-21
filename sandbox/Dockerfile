# Curated TermaAI sandbox image — a bash image plus the everyday CLI tools
# AI-generated scripts most often reach for. The executor still applies its
# own hardening on top (no network, read-only rootfs, dropped capabilities,
# resource limits, non-root user); this image only supplies the toolset.
FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    coreutils \
    findutils \
    grep \
    sed \
    gawk \
    jq \
    python3 \
    git \
    curl \
    ca-certificates \
    tar \
    gzip \
    xz \
    diffutils \
    file \
    less \
    procps-ng

# The executor mounts the workspace at /workspace, runs as the host uid, and
# invokes `bash --noprofile --norc` itself — no entrypoint here.
WORKDIR /workspace
