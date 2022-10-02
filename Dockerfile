FROM golang:1.19-alpine AS base
ARG VERSION=devel
WORKDIR /plasmid
COPY . .
RUN apk add --no-cache make
RUN go build -o plasmid -ldflags "-s -w -X github.com/mdeous/plasmid/cmd.version=${VERSION}" .

FROM alpine:latest
WORKDIR /plasmid
COPY --from=base /plasmid/plasmid .
ENTRYPOINT ["/plasmid/plasmid"]
CMD []
