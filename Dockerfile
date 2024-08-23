FROM golang:1.22.4

WORKDIR /app

COPY . .

RUN go build -o user-checker cmd/stend/main.go

CMD [ "./user-checker" ]