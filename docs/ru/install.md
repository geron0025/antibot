# Установка

Нода ставится до всякой оплаты, у постороннего человека, часто в закрытом
контуре. Отсюда её главное свойство: **ни одной внешней зависимости**. Ни
базы, ни кеша, ни очереди, ни обязательного сетевого адресата.

## Контейнером

```bash
docker run -d --name antibot \
  -p 80:8080 -p 443:8443 \
  -v /etc/antibot:/etc/antibot:ro \
  -v antibot-state:/var/lib/antibot \
  ghcr.io/geron0025/antibot:latest
```

**Монтировать нужно каталог `/var/lib/antibot` целиком, а не отдельные
файлы в нём.** Правила заменяются атомарно, через `rename`, а bind-mount
одиночного файла в Linux привязан к иноду: новый файл окажется другим
инодом, и нода до перезапуска будет применять старые правила, ничем этого
не показывая. Это стоило одного разбора; подробнее — в
[operations.md](operations.md).

## Бинарником

```bash
go build -trimpath -ldflags "-s -w -X main.Version=$(git describe --tags --always)" \
  -o antibot ./cmd/antibot
```

Нужен Go 1.25 или новее. Внешних зависимостей у сборки три:
`golang.org/x/net` (HTTP/2 и punycode), `gopkg.in/yaml.v3` (конфигурация)
и `golang.org/x/text` (транзитивно). Ни одной для работы.

```bash
sudo install -m 0755 antibot /usr/local/bin/antibot
sudo mkdir -p /etc/antibot /var/lib/antibot
sudo antibot serve -config /etc/antibot/config.yaml
```

Как служба systemd:

```ini
[Unit]
Description=antibot
After=network.target

[Service]
ExecStart=/usr/local/bin/antibot serve -config /etc/antibot/config.yaml
Restart=always
User=antibot
# Порты ниже 1024 без прав root:
AmbientCapabilities=CAP_NET_BIND_SERVICE
StateDirectory=antibot

[Install]
WantedBy=multi-user.target
```

## Что положить в конфигурацию

Минимум — куда проксировать:

```yaml
upstreams:
  - host: "*"
    to: "http://127.0.0.1:3000"
```

Всё остальное имеет умолчания, и нода обязана работать с пустым файлом.
Полный разбор — [configuration.md](configuration.md).

## Сертификаты

Нода терминирует TLS сама и выбирает сертификат по имени из SNI.

```yaml
tls:
  certificates_dir: "/etc/letsencrypt/live"
```

Понимаются две раскладки: подкаталог на домен с `fullchain.pem` и
`privkey.pem` (так делает certbot) либо `cert.pem` и `key.pem`. Каталог
просматривается заново по таймеру, поэтому продление certbot'ом и
подключение нового домена вступают в силу **без перезапуска**.

По таймеру, а не слежением за файлами, нарочно: сертификаты почти всегда
обновляются подменой — `rename` поверх или переключение симлинка, — а
слежение идёт за инодой и такой подмены не замечает вовсе.

Если сертификатов нет, выпускается самоподписанный и сохраняется в
`self_signed_dir`. Он нужен, чтобы нода поднималась вообще без настройки:
без него первый же запрос по HTTPS обрывался бы на рукопожатии, и
человек, поставивший контейнер, решил бы, что тот сломан. Браузер на него
ругается — о чём в журнал пишется предупреждение.

ACME нода не умеет и пока не будет: выпуск сертификатов — отдельная
ответственность со своим состоянием, а certbot рядом решает ту же задачу
и уже стоит у большинства.

## Первый запуск

```bash
antibot serve -config /etc/antibot/config.yaml
```

В журнале при старте:

```
level=INFO msg="the node has started" http=:8080 https=:8443
  events=/var/lib/antibot/events rules=0 facts=0 version=0.1.0
```

`rules=0` и `facts=0` — нормальное состояние только что поставленной
ноды. **Она никого не блокирует**: правил нет, значит и запретов нет.
Нода проксирует и пишет события; смотреть их можно сразу.

## Дальше

1. Заведите вход в админку и посмотрите на свой трафик:
   `antibot admin passwd ИМЯ`, потом [admin.md](admin.md).
2. Через сутки напишите первое правило — обязательно в режиме `shadow` —
   и прогоните его по накопленному журналу: [rules.md](rules.md).
3. Когда увидите, кого оно задевает, переведите в `active`.

Порядок именно такой. Антибот, чью работу не видно, не включают в режим
блокировки — и правильно делают.
