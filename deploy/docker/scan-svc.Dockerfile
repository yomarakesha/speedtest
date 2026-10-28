FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /scan-svc ./cmd/scan-svc

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /scan-svc /scan-svc
ENV PORT=8082
EXPOSE 8082
ENTRYPOINT ["/scan-svc"]
