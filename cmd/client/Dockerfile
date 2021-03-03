FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /go/src/psatoken-client
COPY . .
RUN go get -d -v ./...
RUN go install -v ./...

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /go/bin/psatoken-client /psatoken-client
COPY --from=builder /go/src/psatoken-client/data/claims.json /claims.json
COPY --from=builder /go/src/psatoken-client/data/pkey.json /pkey.json
ENV CLAIMSFILE /claims.json
ENV KEYFILE /pkey.json
ENV APIURL http://verifier/challenge-response/v1/newSession
CMD ./psatoken-client -claims ${CLAIMSFILE} -key ${KEYFILE} -url ${APIURL}

LABEL Name=psatoken-client
LABEL Version=0.0.1
LABEL org.opencontainers.image.source=https://github.com/veraison/psatoken