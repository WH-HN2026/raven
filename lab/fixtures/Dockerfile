FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /fixtures . \
 && mkdir /certs \
 && /fixtures generate-certs /certs

FROM alpine:3.22
COPY --from=build /fixtures /usr/local/bin/fixtures
COPY --from=build --chown=65532:65532 /certs /certs
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fixtures"]
