# Установка

Нода ставится до всякой оплаты, у постороннего человека, часто в закрытом
контуре. Отсюда её главное свойство: **ни одной внешней зависимости**. Ни
базы, ни кеша, ни очереди, ни обязательного сетевого адресата.

Программ две:

- **`antibot`** — ядро: терминирует TLS, применяет правила, пишет события.
  Работает само, с правилами из файлов;
- **`antibot-admin`** — [админка](admin.md), необязательная. Отдельный
  процесс под отдельным пользователем; с ядром говорит через сокет и
  общие файлы.

Ставить можно одно ядро. Админку — когда нужно смотреть на трафик и
менять правила не из командной строки.

## Контейнером

```bash
docker run -d --name antibot --restart unless-stopped \
  -p 80:8080 -p 443:8443 \
  -v /etc/antibot:/etc/antibot:ro \
  -v antibot-state:/var/lib/antibot \
  ghcr.io/geron0025/antibot:latest
```

`--restart unless-stopped` — не украшение: упавшее ядро поднимает
докер, и больше некому. Админка перезапускать ядро не умеет и не должна.

Админка — отдельным образом, с тем же томом ядра и своим:

```bash
docker run -d --name antibot-admin --restart unless-stopped \
  -p 127.0.0.1:8090:8090 \
  -v /etc/antibot:/etc/antibot:ro \
  -v antibot-state:/var/lib/antibot \
  -v antibot-admin-state:/var/lib/antibot-admin \
  ghcr.io/geron0025/antibot-admin:latest

docker exec -it antibot-admin antibot-admin accounts passwd owner
```

В контейнере админке надо слушать не loopback — `listen: "0.0.0.0:8090"`
в `admin.yaml`, — а значит, с сертификатом: иначе она не запустится.
Пользователи в образах уже заведены как надо — `antibot` (10001) и
`antibot-admin` (10002) в одной группе, — и каталоги тома получают
нужные права при первом монтировании.

**Монтировать нужно каталог `/var/lib/antibot` целиком, а не отдельные
файлы в нём.** Правила заменяются атомарно, через `rename`, а bind-mount
одиночного файла в Linux привязан к иноду: новый файл окажется другим
инодом, и нода до перезапуска будет применять старые правила, ничем этого
не показывая. Это стоило одного разбора; подробнее — в
[operations.md](operations.md).

## Бинарником

```bash
make build    # antibot и antibot-admin
```

Нужен Go 1.26 или новее. Внешних зависимостей у сборки три:
`golang.org/x/net` (HTTP/2 и punycode), `gopkg.in/yaml.v3` (конфигурация)
и `golang.org/x/text` (транзитивно). Ни одной для работы.

Пользователи и каталоги. Ядро и админка — два пользователя одной
группы; писать обе стороны могут только в `shared`, остальной каталог
ядра админке только для чтения, а свой каталог админки ядру недоступен.
Почему так — [admin.md](admin.md#отдельная-программа).

```bash
sudo groupadd --system antibot
sudo useradd --system -g antibot -d /var/lib/antibot -s /usr/sbin/nologin antibot
sudo useradd --system -g antibot -d /var/lib/antibot-admin -s /usr/sbin/nologin antibot-admin

sudo install -m 0755 antibot antibot-admin /usr/local/bin/
sudo install -d -m 0755 /etc/antibot
sudo install -d -o antibot -g antibot -m 0750 /var/lib/antibot
sudo install -d -o antibot -g antibot -m 0770 /var/lib/antibot/shared
sudo install -d -o antibot-admin -g antibot -m 0700 /var/lib/antibot-admin
```

Как службы systemd. Ядро:

```ini
[Unit]
Description=antibot
After=network.target

[Service]
ExecStart=/usr/local/bin/antibot serve -config /etc/antibot/config.yaml
Restart=always
User=antibot
Group=antibot
# Порты ниже 1024 без прав root:
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

`Restart=always` поднимает упавшее ядро, и кнопка перезапуска в админке
на этом же и держится: ядро по просьбе завершается, systemd запускает
его снова.

Админка, `/etc/systemd/system/antibot-admin.service`:

```ini
[Unit]
Description=antibot admin UI
After=network.target antibot.service

[Service]
ExecStart=/usr/local/bin/antibot-admin serve -config /etc/antibot/admin.yaml
Restart=always
User=antibot-admin
Group=antibot

[Install]
WantedBy=multi-user.target
```

`After=`, но не `Requires=`: админка от ядра не зависит и при лежащем
ядре показывает, что оно лежит, а не падает вместе с ним.

```bash
sudo -u antibot-admin antibot-admin accounts passwd owner
sudo systemctl enable --now antibot antibot-admin
```

### Установка до разделения

До того как админка стала отдельной программой, всё жило в одном
процессе и в одном каталоге. Такая установка обновляется так:

1. Секцию `admin_ui` из `config.yaml` перенести в `admin.yaml`
   ([configuration.md](configuration.md#adminyaml--настройки-админки)) —
   с ней ядро не запустится и скажет об этом.
2. `rules.json`, `domains.json`, `alerts.json` и каталог загруженных
   сертификатов перенести в `/var/lib/antibot/shared` и поправить пути в
   `config.yaml` — или оставить пути как были, если админка не ставится.
3. Учётки и токены API перенести в `/var/lib/antibot-admin`, владелец —
   `antibot-admin`; или завести учётку заново.
4. Команды `antibot admin …` и `antibot api-token …` теперь
   `antibot-admin accounts …` и `antibot-admin api-token …`.

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
   `antibot-admin accounts passwd ИМЯ`, потом [admin.md](admin.md).
2. Через сутки напишите первое правило — обязательно в режиме `shadow` —
   и прогоните его по накопленному журналу: [rules.md](rules.md).
3. Когда увидите, кого оно задевает, переведите в `active` — кнопкой на
   странице правил в админке или командой `antibot rules mode ID active`.
   Нода применит это сразу, без перезапуска.

Порядок именно такой. Антибот, чью работу не видно, не включают в режим
блокировки — и правильно делают.
