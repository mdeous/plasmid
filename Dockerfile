FROM golang:1.19-alpine AS base
WORKDIR /plasmid
COPY . .
RUN apk add --no-cache make
RUN make

FROM alpine:latest
WORKDIR /plasmid
COPY --from=base /plasmid/plasmid .
ENTRYPOINT ["/plasmid/plasmid"]
CMD []
