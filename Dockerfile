FROM golang:1.8-alpine

RUN apk add --no-cache git build-base libpcap-dev

WORKDIR /go/src/app
COPY . .

RUN go build -v

CMD ["go-wrapper", "run"] # ["app"]
