FROM golang:1.20-bullseye as builder
RUN git config --global --add safe.directory /app
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . ./
RUN go build -v -o mlmym

FROM debian:bullseye-slim
WORKDIR /app
RUN set -x && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/mlmym /app/mlmym
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/public /app/public
CMD ["./mlmym", "--addr", "0.0.0.0:8080"]
