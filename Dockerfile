# PatchTriage — reproducible container build.
#
#   docker build -t patchtriage .
#   mkdir -p out && docker run --rm -v "$PWD/out:/out" patchtriage   # offline demo
#   docker run --rm -e PATCHTRIAGE_AI_PROVIDER -e OPENAI_API_KEY \
#       -e PATCHTRIAGE_AI_MODEL -v "$PWD:/work" patchtriage \
#       run /work/trivy.json --triage ai -o /work/report.json

FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[ai]"

# Pin the static repository scanner used only by the opt-in local importer.
# Source scanning reads manifests/lockfiles; PatchTriage never invokes the
# scanner's remediation command or a package manager on untrusted content.
FROM ghcr.io/google/osv-scanner:v2.3.8 AS osv-scanner

FROM python:3.12-slim
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
    && chown -R patchtriage:patchtriage /out /work /home/patchtriage
# Pre-creating + chowning the cache/config dirs means Docker initializes the
# named volumes mounted there with uid 1000 ownership, so the GUI (which runs
# as this user) can persist targets, caches and reports.
USER patchtriage
WORKDIR /work
# `docker run patchtriage` runs the fully offline demo by default
ENTRYPOINT ["patchtriage"]
CMD ["demo", "--html", "/out/demo_report.html", "--output", "/out/demo_report.json"]
