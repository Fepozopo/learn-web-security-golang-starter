FROM golang:1.27.0-alpine AS build

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bearly-secure ./cmd/server && \
    CGO_ENABLED=0 go build -o /bearly-attacker-lab ./cmd/attackerlab

FROM alpine:3.22

RUN apk add --no-cache ca-certificates && \
    addgroup -S bearly && adduser -S -G bearly bearly
WORKDIR /app
COPY --from=build /bearly-secure /bearly-attacker-lab ./
COPY attacker-lab/ ./attacker-lab/
COPY web/ ./web/
COPY data/uploads/mystery-shack-tax-exemption.pdf ./data/uploads/
RUN chown -R bearly:bearly /app/data
USER bearly
EXPOSE 3030 4040
CMD ["./bearly-secure"]
