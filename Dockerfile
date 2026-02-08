FROM golang:1.24-alpine AS base
ARG VERSION=devel
WORKDIR /plasmid
COPY . .
RUN go build -o plasmid -ldflags "-s -w -X github.com/mdeous/plasmid/cmd.version=${VERSION}" .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /plasmid
COPY --from=base /plasmid/plasmid .
ENTRYPOINT ["/plasmid/plasmid"]
CMD []
