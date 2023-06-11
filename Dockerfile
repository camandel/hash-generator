FROM golang:1.19-alpine as builder
COPY *.go go.* /src/
WORKDIR /src
RUN go build -o hash-generator

FROM alpine
RUN adduser -D www
COPY --from=builder /src/hash-generator /app/
COPY static/ /app/static/
COPY templates/ /app/templates/
EXPOSE 8000
USER www
WORKDIR /app
ENTRYPOINT ./hash-generator
