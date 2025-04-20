FROM golang:1.24-alpine AS base
ARG VERSION=devel
WORKDIR /plasmid
COPY . .
RUN go build -o plasmid -ldflags "-s -w -X github.com/mdeous/plasmid/cmd.version=${VERSION}" .

FROM scratch
WORKDIR /plasmid
COPY --from=base /plasmid/plasmid .
ENTRYPOINT ["/plasmid/plasmid"]
CMD []
