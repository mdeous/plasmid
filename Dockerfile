FROM golang:1.19-alpine AS base
ARG VERSION=devel
WORKDIR /plasmid
COPY . .
RUN CGO_ENABLED=0 go build -o plasmid -ldflags "-s -w -X github.com/mdeous/plasmid/cmd.version=${VERSION}" .

FROM scratch
WORKDIR /plasmid
COPY --from=base /plasmid/plasmid .
ENTRYPOINT ["/plasmid/plasmid"]
CMD []
