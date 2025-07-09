FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG JWT_SECRET_KEY
RUN test -n "$JWT_SECRET_KEY" || (echo "JWT_SECRET_KEY not set" && exit 1)

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X 'main.jwtSecretKey=${JWT_SECRET_KEY}'" -o autification .

FROM alpine:latest
WORKDIR /root/

COPY --from=builder /app/autification .


ENV JWT_SECRET_KEY=""

EXPOSE 8080
CMD ["./autification"]