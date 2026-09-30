FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aegispolicy ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/testissuer ./cmd/testissuer

FROM alpine:3.23
RUN addgroup -S aegis && adduser -S -G aegis aegis
COPY --from=build /out/aegispolicy /usr/local/bin/aegispolicy
COPY --from=build /out/testissuer /usr/local/bin/testissuer
USER aegis
ENTRYPOINT ["/usr/local/bin/aegispolicy"]
