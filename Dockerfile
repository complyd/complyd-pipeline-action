# complyd-pipeline for CI systems without Node (Jenkins, CodeBuild, Azure DevOps, …):
#   docker run --rm -v "$PWD:/src:ro" -w /src -e COMPLYD_INGEST_KEY ghcr.io/complyd/pipeline@sha256:<digest> scan dependencies --input osv.json --repo … --commit …
# No shell in the image: GitLab CI jobs use a node image instead (see README).
# Pinned by digest (the multi-arch index). To update:
#   curl -sI -H 'Accept: application/vnd.oci.image.index.v1+json' \
#     https://gcr.io/v2/distroless/nodejs22-debian12/manifests/nonroot | grep -i docker-content-digest
FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:13593b7570658e8477de39e2f4a1dd25db2f836d68a0ba771251572d23bb4f8e
LABEL org.opencontainers.image.title="Complyd pipeline" \
      org.opencontainers.image.description="complyd-pipeline: send a pipeline's dependency or SAST scan to Complyd" \
      org.opencontainers.image.source="https://github.com/complyd/complyd-pipeline-action" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Complyd"
WORKDIR /app
COPY package.json ./
COPY src ./src
ENTRYPOINT ["/nodejs/bin/node", "/app/src/cli.js"]
