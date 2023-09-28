FROM golang:1.20.5-alpine3.17 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=librescan/shared-protobuf /api.pb.go /api_grpc.pb.go /src/api/
RUN go build

########## ########## ##########

FROM alpine:3.18.3
COPY --from=builder /src/backend-api /backend-api
ENTRYPOINT [ "/backend-api" ]
