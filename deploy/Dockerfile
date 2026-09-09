# Сборка
#
# Собирается на архитектуре сборщика, а не образа: кросс-компиляция Go
# бесплатна, а сборка под чужую архитектуру через эмуляцию идёт минутами.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

WORKDIR /src

# Зависимости отдельным слоем: правка кода не заставляет их скачивать заново.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /antibot ./cmd/antibot

# Образ
FROM alpine:3.20

# ca-certificates нужны, только если включены обновления баз: без них
# нода не сможет проверить сертификат сервиса обновлений. tzdata — чтобы
# время в журнале совпадало со временем хозяина.
RUN apk add --no-cache ca-certificates tzdata

# Нода не делает ничего, что требует прав суперпользователя: порты 80 и
# 443 внутри контейнера публикуются наружу докером, а не занимаются
# процессом напрямую.
RUN adduser -D -u 10001 antibot && mkdir -p /var/lib/antibot && chown antibot /var/lib/antibot
USER antibot

COPY --from=build /antibot /usr/local/bin/antibot

VOLUME /var/lib/antibot
EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/bin/antibot"]
CMD ["serve", "-config", "/etc/antibot/config.yaml"]
