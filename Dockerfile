FROM alpine:3.6
LABEL maintainer "Jonathan Pulsifer <jonathan@pulsifer.ca>"
RUN addgroup -S dnsmon && adduser -S -G dnsmon dnsmon
COPY dnsmon-go /usr/bin
USER dnsmon
ENTRYPOINT ["dnsmon-go"]

