FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /audit-svc ./cmd/audit-svc

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /audit-svc /audit-svc
ENV PORT=8081
EXPOSE 8081
ENTRYPOINT ["/audit-svc"]
