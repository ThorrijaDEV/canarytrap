# canarytrap

Canary tokens **autoalojados**: cebos tentadores que avisan en el momento exacto en que alguien los toca. Un servidor minúsculo (solo stdlib), generadores de señuelos creíbles y alertas por webhook — tu propio sistema de detección de intrusos para archivos, repos y servidores, sin depender de servicios de terceros ni enviar nada fuera de tu infraestructura.

```
$ canarytrap new aws-key --label "creds-prod-falsa"
Token 5znwb7e5rynfqpxg (aws-key) · etiqueta: creds-prod-falsa
  Contenido a colocar (p. ej. ~/.aws/credentials falso):
    [default]
    aws_access_key_id = AKIA5ZNWB7E5RYNFQPXG
    ...

$ canarytrap serve --webhook https://tu-webhook/hook
canarytrap escuchando en 0.0.0.0:8420 (3 tokens armados)

[!] CEBO PISADO  creds-prod-falsa   desde 203.0.113.7   python-requests/2.31
```

## Por qué

Los canary tokens comerciales (Thinkst Canary, CanaryTokens.org) son geniales pero implican confiar tus alertas —y las IPs de quien toca el cebo— a un tercero. `canarytrap` es la versión minimalista para quien ya tiene un VPS: tú controlas el dominio, los logs y el webhook. Si alguien descarga tu `.env` falso o tu "credentials de AWS", sabes **quién, cuándo y con qué User-Agent** — y que probablemente tienes un problema de fuga interna.

## Cebos incluidos

| Tipo | Señuelo | Cómo se pisa |
|---|---|---|
| `url` | Enlace a un `.zip` inexistente | GET a la URL del cebo |
| `image` | Píxel rastreador disfrazado | Carga en docs/emails/web |
| `aws-key` | `~/.aws/credentials` con claves AKIA falsas | Abrir el archivo robado |
| `env` | `.env` con secretos de producción inventados | Exfiltración de configs |

Cada toque queda en `hits.jsonl` (IP, timestamp, User-Agent, ruta), incrementa el contador del token y dispara tu webhook con un POST JSON:

```json
{"event": "canarytrip", "token": "...", "label": "servidor-prod",
 "ip": "203.0.113.7", "ua": "curl/8.21.0", "path": "/bait/....env", "ts": ...}
```

## Flujo típico

```bash
pip install canarytrap            # o desde el repo

canarytrap new env --label "backup-servidor" --host trampas.tudominio.es
# coloca el .env falso donde un atacante lo busque
canarytrap serve --port 8420 --webhook https://hooks.tuservicio/xyz &

# consulta quién cayó
canarytrap hits -n 50
```

Coloca cebos en: repos con historial "privado", buckets mal nombrados a propósito, homes de usuarios trampa (`ssh trap@server`), documentación interna, carpetas compartidas. La regla de oro: **cualquier acceso a un cebo es señal de incidente** — nadie legítimo abre esas cosas.

## Webhook → notificaciones

El POST JSON es compatible directo con:
- **ntfy.sh / Gotify**: `--webhook https://ntfy.tu/canarytrap` (+ filtro)
- **Telegram bot**, **Discord/Slack webhook** (con un adaptador mínimo)
- Tu propio script de respuesta a incidentes

## Ética y legalidad

Despliega cebos **solo en sistemas que te pertenezcan** o donde tengas autorización explícita. Los cebos registran metadatos de acceso (IP, UA); trata esa información según tu jurisdicción (RGPD si aplica). No incluyas datos personales reales en los señuelos.

## Limitaciones v0.1

- HTTP plano: ponlo detrás de nginx/Caddy con TLS.
- Sin DNS tokens (requieren servidor autoritativo propio) — roadmap.
- Un solo proceso: para alta disponibilidad, ejecuta varias instancias contra el mismo estado… o mejor, esto no es tu SIEM primario.

Roadmap: tokens DNS + SMTP, imagen PNG real como cebo, panel HTML de hits, integración ntfy nativa, firma GPG de los cebos para detectar también su *modificación*.

## Desarrollo

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e . pytest
pytest   # 10 tests: store, cebos, servidor real + webhook receptor local
```

```
src/canarytrap/
├── store.py     # Token/TokenStore + plantillas de cebo
├── server.py    # TrapServer (ThreadingHTTPServer) + registro/alertas
└── cli.py       # new | serve | hits
tests/
```

## Licencia

[MIT](LICENSE)
