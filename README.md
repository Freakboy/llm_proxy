# LLM Proxy

A Python/Flask LLM proxy with channel routing, model mappings, upstream failover,
and a web administration interface.

## Quick Start

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json
python llm_proxy.py
```

Open `http://127.0.0.1:3838/admin` to configure channels. The example configuration
listens on loopback and has no channels or access keys. Without access keys, the
API and admin interface are accessible without authentication. Configure an
access key on the security page before exposing the service to other machines.

An alternate configuration can be selected with `--config /path/to/config.json`.
Configuration changes are saved to JSON and external file changes are reloaded.

## Administration

- `/admin`: channels, proxy settings, model discovery, and pasted configuration
  or sub2api/CCS link import.
- `/admin/mappings`: global model aliases and per-channel overrides.
- `/admin/logs`: request results, response sizes, and full error details.
- `/admin/security`: shared access keys and admin login.

Supported channel types are `openai-chat`, `openai-oai`, `openai-responses`,
`claude`, and `gemini`. Global and per-channel HTTP(S)/SOCKS proxies are supported.

## Tests

```sh
python -m unittest test_llm_proxy
```

Local configuration, request logs, backups, and generated files are excluded
from Git. Keep upstream credentials in the local configuration, not in source.
