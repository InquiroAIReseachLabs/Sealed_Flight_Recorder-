# The sfr demo image, x86_64 (Chunk 5). scripts/build_demo_image.sh assembles the build context:
# the static sfr, the two golden logs the demo uses with their license and provenance notices,
# the default rules and the two logs' baselines, and scripts/run_demo.sh. busybox supplies
# /bin/sh and the tools the demo script runs (awk, cp, date, dd, mktemp, od, sed, strings, tr);
# nothing else is installed. Run it with: docker run --rm --network=none sfr-demo:<version>
FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092
COPY sfr /sfr
ARG SFR_VERSION
ENV PATH=/sfr/bin:/bin SFR_DEMO_IMAGE=sfr-demo:${SFR_VERSION}
USER 65534:65534
WORKDIR /sfr
CMD ["/sfr/scripts/run_demo.sh"]
