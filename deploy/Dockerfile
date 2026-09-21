# Сборка
#
# Собирается на архитектуре сборщика, а не образа: кросс-компиляция Go
# бесплатна, а сборка под чужую архитектуру через эмуляцию идёт минутами.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

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
    -o /antibot ./cmd/antibot && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /antibot-admin ./cmd/antibot-admin

# Общее у обоих образов: пользователи и каталоги.
#
# Ядро и админка — два пользователя одной группы antibot. Каталог ядра
# группе только на чтение: события и сокет. Писать обе стороны могут
# только в shared — правила, домены, команду оповещений, загруженные
# сертификаты. Токен облака и идентификатор ноды лежат выше, и админка
# их не прочитает и не подменит. Свои файлы админки — в
# /var/lib/antibot-admin, куда ядро не заглядывает.
#
# Каталоги заводятся в обоих образах одинаково: том получает права из
# того образа, который смонтирует его первым.
FROM alpine:3.20 AS base
RUN addgroup -g 10001 antibot && \
    adduser -D -u 10001 -G antibot antibot && \
    adduser -D -u 10002 -G antibot antibot-admin && \
    mkdir -p /var/lib/antibot/shared /var/lib/antibot-admin && \
    chown antibot:antibot /var/lib/antibot /var/lib/antibot/shared && \
    chmod 0750 /var/lib/antibot && chmod 0770 /var/lib/antibot/shared && \
    chown antibot-admin:antibot /var/lib/antibot-admin && chmod 0700 /var/lib/antibot-admin

# Админка
#
# Отдельный образ: в образе ядра её кода нет вовсе.
#   docker build --target admin -f deploy/Dockerfile .
FROM base AS admin
# Наружу админка не ходит, поэтому ca-certificates ей не нужны; tzdata —
# чтобы время на страницах совпадало со временем хозяина.
RUN apk add --no-cache tzdata
USER antibot-admin
COPY --from=build /antibot-admin /usr/local/bin/antibot-admin
VOLUME /var/lib/antibot-admin
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/antibot-admin"]
CMD ["serve", "-config", "/etc/antibot/admin.yaml"]

# Ядро — цель по умолчанию, последней.
FROM base AS core

# ca-certificates нужны, только если включены обновления баз: без них
# нода не сможет проверить сертификат сервиса обновлений. tzdata — чтобы
# время в журнале совпадало со временем хозяина. curl — для команды
# доставки оповещений: готовые шаблоны в документации (Telegram, вебхук,
# почта) написаны на нём, и busybox-овский wget их не заменит.
RUN apk add --no-cache ca-certificates tzdata curl

# Нода не делает ничего, что требует прав суперпользователя: порты 80 и
# 443 внутри контейнера публикуются наружу докером, а не занимаются
# процессом напрямую.
USER antibot

COPY --from=build /antibot /usr/local/bin/antibot

VOLUME /var/lib/antibot
EXPOSE 8080 8443

ENTRYPOINT ["/usr/local/bin/antibot"]
CMD ["serve", "-config", "/etc/antibot/config.yaml"]
