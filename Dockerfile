FROM golang:alpine AS build
# hadolint ignore=DL3018
RUN apk update && apk add --no-cache build-base git libpcap-dev
WORKDIR /go/src/github.com/jonpulsifer/dnsmon
COPY . .
RUN go mod tidy
RUN GOOS=linux go build -installsuffix cgo -ldflags '-w -s' -o /go/bin/dnsmon

FROM alpine
RUN apk update && apk add --no-cache libpcap
COPY --from=build /go/bin/dnsmon /usr/bin/dnsmon
ENTRYPOINT ["/usr/bin/dnsmon"]
CMD ["--help"]
