# syntax=docker/dockerfile:1
FROM golang:1.21-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
ENV GOFLAGS=-mod=mod
ENV CGO_ENABLED=0
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN go mod tidy
RUN go build -o /out/server .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates iputils busybox-extras
WORKDIR /app
RUN mkdir -p /app/uploads /app/templates
COPY --from=build /out/server /app/server
EXPOSE 8080
ENTRYPOINT ["/app/server"]
