FROM golang:alpine AS build
# hadolint ignore=DL3018
RUN apk update && apk add --no-cache build-base git libpcap-dev
WORKDIR /go/src/github.com/jonpulsifer/dnsmon-go
COPY . .
RUN go mod tidy
RUN GOOS=linux go build -installsuffix cgo -ldflags '-w -s' -o /go/bin/dnsmon-go

FROM alpine:edge
# hadolint ignore=DL3018
RUN apk update && apk add --no-cache libpcap
COPY --from=build /go/bin/dnsmon-go /usr/bin/dnsmon-go
EXPOSE 8080/tcp
ENTRYPOINT ["/usr/bin/dnsmon-go"]
CMD ["--help"]
