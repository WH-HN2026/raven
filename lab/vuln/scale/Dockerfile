FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod *.go jenkins-favicon.ico ./
RUN CGO_ENABLED=0 go build -trimpath -o /scale .

FROM alpine:3.22
RUN apk add --no-cache iproute2
COPY --from=build /scale /usr/local/bin/scale
ENTRYPOINT ["/usr/local/bin/scale"]
CMD ["serve"]
