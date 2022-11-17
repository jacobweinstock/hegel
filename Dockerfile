FROM alpine:3.16.3

# Define args for the target platform so we can identify the binary in the Docker context.
# These args are populated by Docker. The values should match Go's GOOS and GOARCH values for
# the respective os/platform.
ARG TARGETARCH
ARG TARGETOS

RUN apk add --update --upgrade ca-certificates

RUN adduser -D -u 1000 tinkerbell

COPY ./hegel-$TARGETOS-$TARGETARCH /usr/bin/hegel

# Github's artifact upload action doesn't preserve permissions. While this is a Github specific
# problem, there's no succinct way to fix it in the actions as we build for multiple platforms.
# For now, we'll suffer the extra layer and just chmod the binary.
RUN chmod +x /usr/bin/hegel

# Switching to the tinkerbell user should be done as late as possible so we still use root to
# perform the other commands.
USER tinkerbell
ENTRYPOINT ["/usr/bin/hegel"]
