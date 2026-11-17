# PatchTriage — reproducible container build.
#
#   docker build -t patchtriage .
#   docker run --rm --user 0 -v "$PWD/out:/out" patchtriage   # offline demo -> ./out
#   (--user 0 lets the entrypoint run as the owner of ./out, then drop root)
#   docker run --rm -e PATCHTRIAGE_AI_PROVIDER -e OPENAI_API_KEY \
#       -e PATCHTRIAGE_AI_MODEL -v "$PWD:/work" patchtriage \
#       run /work/trivy.json --triage ai -o /work/report.json

# Base images are pinned by digest for reproducible builds; Dependabot
# (.github/dependabot.yml) proposes digest and tag updates weekly.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[ai]"

# Pin the static repository scanner used only by the opt-in local importer.
# Source scanning reads manifests/lockfiles; PatchTriage never invokes the
# scanner's remediation command or a package manager on untrusted content.
FROM ghcr.io/google/osv-scanner:v2.3.8@sha256:64e86bec6df2466feea5137fc7c78fb3b7c21ec077f014d7130f64810e50676b AS osv-scanner

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL org.opencontainers.image.title="PatchTriage" \
      org.opencontainers.image.description="Evidence-driven patch triage with deterministic SSVC decisions and audited AI explanations" \
      org.opencontainers.image.source="https://github.com/d01ki/PatchTriage" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /install /usr/local
COPY --from=osv-scanner /osv-scanner /usr/local/bin/osv-scanner
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates git nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 patchtriage \
    && mkdir -p /out /work \
       /home/patchtriage/.cache/patchtriage \
       /home/patchtriage/.config/patchtriage \
    && chown -R patchtriage:patchtriage /out /home/patchtriage \
    && chmod 700 /home/patchtriage/.config/patchtriage
# /work stays root-owned: the entrypoint reads its owner to find the clone's
# user, and an unmounted /work must not look like a user's folder.
# Pre-creating + chowning the cache/config dirs means Docker initializes the
# named volumes mounted there with uid 1000 ownership, so the GUI (which runs
# as this user) can persist targets, caches and reports.
COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# A Windows checkout may have converted the script to CRLF, which would make
# every CLI service fail with "no such file or directory".
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh
ENV HOME=/home/patchtriage
USER patchtriage
WORKDIR /work
# `docker run patchtriage` runs the fully offline demo by default. The
# entrypoint only changes anything when the container starts as root.
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["demo", "--html", "/out/demo_report.html", "--output", "/out/demo_report.json"]
