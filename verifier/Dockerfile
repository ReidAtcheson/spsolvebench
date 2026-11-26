# Multi-stage build: compiles unmodified C `stencil` with blst v0.3.16
# and packages it with the lightweight Python batch verifier (~120 MB final image).
FROM debian:bookworm-slim AS builder

ARG BLST_COMMIT=e7f90de551e8df682f3cc99067d204d8b90d27ad
ARG STENCIL_REPO=https://github.com/ReidAtcheson/sparse-solver-challenge.git
ARG STENCIL_COMMIT=b19fb9a

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates git pkg-config \
      libssl-dev libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Build blst v0.3.16 (pinned commit from BEACON.md)
RUN git clone https://github.com/supranational/blst.git /src/blst \
    && cd /src/blst \
    && git checkout "${BLST_COMMIT}" \
    && ./build.sh

# Build stencil (prover/validator only — no SuperLU/BLAS needed)
RUN git clone "${STENCIL_REPO}" /src/sparse-solver-challenge \
    && cd /src/sparse-solver-challenge \
    && git checkout "${STENCIL_COMMIT}" \
    && make BLST_DIR=/src/blst stencil \
    && strip stencil

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libsodium23 libssl3 openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/sparse-solver-challenge/stencil /usr/local/bin/stencil

WORKDIR /app
COPY verifier/requirements.txt /app/verifier/requirements.txt
RUN pip install --no-cache-dir -r /app/verifier/requirements.txt

COPY config/ /app/config/
COPY verifier/ /app/verifier/

# Verify pinned Sigstore root CA fingerprint at image build time
RUN test "$(openssl x509 -in /app/config/sigstore-root.crt -outform DER | sha256sum | awk '{print $1}')" \
      = "2aca8fea5d3ce48b01cc77076293c280e6c23ffe44034757ee7833ca9f45d633"

ENV STENCIL_BIN=/usr/local/bin/stencil \
    PROTOCOL_CONFIG=/app/config/protocol.json \
    SIGSTORE_CA=/app/config/sigstore-root.crt \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "/app/verifier/verify_batch.py"]
