FROM golang:1.19
EXPOSE 8000/tcp
WORKDIR /plasmid
COPY . .
RUN make
ENTRYPOINT ["/plasmid/plasmid"]
CMD []
