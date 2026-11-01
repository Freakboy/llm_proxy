#!/usr/bin/env python3
import json
import copy
import time
import argparse
import httpx
import base64
import hashlib
import hmac
import secrets
from datetime import timedelta
from flask import Flask, request, Response, jsonify, render_template, redirect, session, url_for
import os
import threading
from urllib.parse import urlsplit, urlunsplit
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from uuid import uuid4
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)
CONFIG = {}
CONFIG_PATH = "config.json"
CONFIG_MTIME_NS = None
CONFIG_FILE_STATE = None
CONFIG_FAILED_STATE = None
CONFIG_SYNC_ERROR = None
CONFIG_LOCK = threading.RLock()
CONFIG_WATCHER_STARTED = False
REQUEST_LOGS = deque(maxlen=2000)
REQUEST_LOG_LOCK = threading.RLock()
MODEL_REFRESH_JOBS = {}
MODEL_REFRESH_LOCK = threading.RLock()
UPSTREAM_FAILURES = {}
UPSTREAM_FAILURE_LOCK = threading.RLock()
AUTH_HEADER_NAMES = {"authorization", "x-api-key", "api-key", "x-goog-api-key"}
CHANNEL_TYPES = {"claude", "gemini", "openai-chat", "openai-oai", "openai-responses"}

# 配置读写
def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def config_file_state():
    stat = os.stat(CONFIG_PATH)
    return (stat.st_ino, stat.st_size, stat.st_mtime_ns)

def save_config():
    global CONFIG_MTIME_NS, CONFIG_FILE_STATE, CONFIG_FAILED_STATE, CONFIG_SYNC_ERROR
    with CONFIG_LOCK:
        directory = os.path.dirname(os.path.abspath(CONFIG_PATH))
        temp_path = os.path.join(directory, f".{os.path.basename(CONFIG_PATH)}.{os.getpid()}.tmp")
        mode = os.stat(CONFIG_PATH).st_mode & 0o777 if os.path.exists(CONFIG_PATH) else 0o600
        try:
            with open(temp_path, "w", encoding="utf-8") as config_file:
                json.dump(CONFIG, config_file, indent=4, ensure_ascii=False)
                config_file.flush()
                os.fsync(config_file.fileno())
            os.chmod(temp_path, mode)
            os.replace(temp_path, CONFIG_PATH)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        CONFIG_FILE_STATE = config_file_state()
        CONFIG_MTIME_NS = CONFIG_FILE_STATE[2]
        CONFIG_FAILED_STATE = None
        CONFIG_SYNC_ERROR = None

def sync_config_from_disk():
    global CONFIG_MTIME_NS, CONFIG_FILE_STATE, CONFIG_FAILED_STATE, CONFIG_SYNC_ERROR
    try:
        current_state = config_file_state()
    except FileNotFoundError:
        return False
    if current_state == CONFIG_FILE_STATE or current_state == CONFIG_FAILED_STATE:
        return False

    try:
        with CONFIG_LOCK:
            loaded = load_config(CONFIG_PATH)
            if not isinstance(loaded, dict) or not isinstance(loaded.get("channels"), list):
                raise ValueError("config must contain a channels list")
            CONFIG.clear()
            CONFIG.update(loaded)
            if CONFIG.get("adminSessionSecret"):
                app.secret_key = CONFIG["adminSessionSecret"]
            CONFIG_FILE_STATE = current_state
            CONFIG_MTIME_NS = current_state[2]
            CONFIG_FAILED_STATE = None
            CONFIG_SYNC_ERROR = None
        print(f"Reloaded config from {CONFIG_PATH}")
        return True
    except (OSError, ValueError) as error:
        CONFIG_FAILED_STATE = current_state
        CONFIG_SYNC_ERROR = str(error)
        print(f"Failed to reload config from {CONFIG_PATH}: {error}")
        return False

def config_watch_loop(stop_event=None):
    while not stop_event or not stop_event.is_set():
        sync_config_from_disk()
        if stop_event:
            stop_event.wait(1)
        else:
            time.sleep(1)

def start_config_watcher():
    global CONFIG_WATCHER_STARTED
    if CONFIG_WATCHER_STARTED:
        return
    CONFIG_WATCHER_STARTED = True
    threading.Thread(target=config_watch_loop, name="config-watcher", daemon=True).start()

@app.before_request
def sync_external_config_changes():
    sync_config_from_disk()

def hash_api_key(api_key):
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

def configured_api_keys():
    return [
        entry
        for entry in CONFIG.get("apiKeys", [])
        if isinstance(entry, dict) and entry.get("enabled", True) and entry.get("keyHash")
    ]

def request_credential():
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip(), "authorization-bearer"
    if authorization and " " not in authorization.strip():
        return authorization.strip(), "authorization-raw"
    for header_name in ("x-api-key", "api-key", "x-goog-api-key"):
        value = request.headers.get(header_name)
        if value:
            return value.strip(), header_name
    for query_name in ("key", "api_key"):
        value = request.args.get(query_name)
        if value:
            return value.strip(), f"query-{query_name}"
    return "", "missing"

def request_api_key():
    return request_credential()[0]

def matching_api_key(api_key):
    if not api_key:
        return None
    candidate_hash = hash_api_key(api_key)
    for entry in configured_api_keys():
        if hmac.compare_digest(entry["keyHash"], candidate_hash):
            return entry
    return None

def admin_authenticated():
    session_hash = session.get("apiKeyHash")
    if session_hash and any(
        hmac.compare_digest(entry["keyHash"], session_hash)
        for entry in configured_api_keys()
    ):
        return True
    return matching_api_key(request_api_key()) is not None

@app.before_request
def require_configured_api_key():
    if not configured_api_keys():
        return None
    if request.path in {"/admin/login", "/admin/logout"}:
        return None
    if request.path.startswith("/admin"):
        if admin_authenticated():
            return None
        if request.path.startswith("/admin/api"):
            return jsonify({"error": "Unauthorized"}), 401, {"WWW-Authenticate": "Bearer"}
        return redirect(url_for("admin_login", next=request.full_path))
    if request.path.startswith("/v1/") or request.path.startswith("/providers/"):
        if matching_api_key(request_api_key()):
            return None
        presented_key, source = request_credential()
        prefix = presented_key[:8] if presented_key else "<none>"
        record_request_log(
            "<authentication>",
            "auth",
            None,
            None,
            401,
            time.monotonic(),
            f"authentication failed; source={source}; prefix={prefix}",
            response_bytes=0,
        )
        return jsonify({"error": "Invalid or missing API key"}), 401, {"WWW-Authenticate": "Bearer"}
    return None

def request_log_path():
    configured = CONFIG.get("requestLogPath")
    if configured:
        return configured
    config_dir = os.path.dirname(os.path.abspath(CONFIG_PATH))
    return os.path.join(config_dir, "request_logs.jsonl")

def load_request_logs():
    path = request_log_path()
    if not os.path.exists(path):
        return
    with REQUEST_LOG_LOCK:
        REQUEST_LOGS.clear()
        try:
            with open(path, "r", encoding="utf-8") as log_file:
                for line in log_file:
                    try:
                        REQUEST_LOGS.append(json.loads(line))
                    except (ValueError, json.JSONDecodeError):
                        continue
        except OSError as error:
            print(f"Failed to load request logs: {error}")

def record_request_log(request_model, req_type, channel, upstream_model, status, started_at, error=None, stream=False, response_bytes=None, route=None):
    entry = {
        "id": time.time_ns(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "requestType": req_type,
        "route": route or request.path,
        "requestModel": request_model,
        "channel": channel,
        "upstreamModel": upstream_model,
        "status": status,
        "durationMs": round((time.monotonic() - started_at) * 1000, 1),
        "stream": bool(stream),
        "responseBytes": response_bytes,
        "error": str(error) if error else None,
    }
    path = request_log_path()
    try:
        with REQUEST_LOG_LOCK:
            REQUEST_LOGS.append(entry)
            with open(path, "a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(entry, ensure_ascii=False) + "\n")
            if os.path.getsize(path) > 5 * 1024 * 1024:
                temp_path = path + ".tmp"
                with open(temp_path, "w", encoding="utf-8") as log_file:
                    for item in REQUEST_LOGS:
                        log_file.write(json.dumps(item, ensure_ascii=False) + "\n")
                os.replace(temp_path, path)
    except OSError as log_error:
        print(f"Failed to write request log: {log_error}")
    return entry

def require_json_object():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object")
    return data

def normalize_string_list(value, field_name):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    return [str(item).strip() for item in value if str(item).strip()]

def normalize_headers(value, field_name):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be an object")
    return {str(key).strip(): str(item) for key, item in value.items() if str(key).strip()}

def normalize_proxy(value, field_name="proxy"):
    proxy = str(value or "").strip()
    if not proxy:
        return ""
    parsed = urlsplit(proxy)
    if parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname:
        raise ValueError(f"{field_name} must be an http(s) or socks5 URL")
    return proxy

def effective_proxy(channel):
    return channel.get("proxy") or CONFIG.get("proxy") or None

def public_proxy(proxy):
    if not proxy:
        return {"configured": False, "display": ""}
    parsed = urlsplit(proxy)
    host = parsed.hostname or ""
    if parsed.port:
        host += f":{parsed.port}"
    return {"configured": True, "display": f"{parsed.scheme}://{host}"}

def normalize_model_map(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("model_map must be an object")
    return {
        str(source).strip(): normalize_string_list(targets, f"model_map.{source}")
        for source, targets in value.items()
        if str(source).strip()
    }

def normalize_channel(data, existing=None):
    channel = dict(existing or {})
    name = str(data.get("name", channel.get("name", ""))).strip()
    channel_type = str(data.get("type", channel.get("type", ""))).strip()
    base_url = str(data.get("baseUrl", channel.get("baseUrl", ""))).strip().rstrip("/")
    if not name:
        raise ValueError("Channel name is required")
    if channel_type not in CHANNEL_TYPES:
        raise ValueError(f"Unsupported channel type: {channel_type}")
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("baseUrl must start with http:// or https://")

    api_key = str(data.get("apiKey", "")).strip()
    channel.update(
        {
            "name": name,
            "type": channel_type,
            "baseUrl": base_url,
            "proxy": normalize_proxy(data.get("proxy", channel.get("proxy", "")), "proxy"),
            "website": str(data.get("website", channel.get("website", ""))).strip(),
            "remark": str(data.get("remark", channel.get("remark", ""))).strip(),
            "weight": int(data.get("weight", channel.get("weight", 0))),
            "default": bool(data.get("default", channel.get("default", False))),
            "interval": max(0, int(data.get("interval", channel.get("interval", 0)))),
            "timeout": max(1, int(data.get("timeout", channel.get("timeout", 20)))),
            "model": normalize_string_list(data.get("model", channel.get("model", [])), "model"),
            "models": normalize_string_list(data.get("models", channel.get("models", [])), "models"),
            "model_map": normalize_model_map(data.get("model_map", parse_model_mappings(channel))),
            "add_headers": normalize_headers(data.get("add_headers", channel.get("add_headers", {})), "add_headers"),
            "modify_headers": normalize_headers(data.get("modify_headers", channel.get("modify_headers", {})), "modify_headers"),
            "remove_headers": normalize_string_list(data.get("remove_headers", channel.get("remove_headers", [])), "remove_headers"),
        }
    )
    if api_key:
        channel["apiKey"] = api_key
    elif "apiKey" not in channel:
        channel["apiKey"] = ""

    for legacy_key in ("modelMap", "model_mappings", "modelMappings"):
        channel.pop(legacy_key, None)
    return channel

# 核心匹配逻辑：跳过负权重渠道，weight 为 0 也参与匹配
def match_models_in_channel(request_model, channel_models):
    exact, contain, reverse_contain = [], [], []
    for m in channel_models:
        if m == request_model:
            exact.append(m)
        elif request_model in m:
            contain.append(m)
        elif m in request_model:
            reverse_contain.append(m)
    match_models = exact + contain + reverse_contain
    return match_models

def rank_matched_models(request_model, models):
    ordered = []
    seen = set()
    for model in models:
        if model not in seen:
            ordered.append(model)
            seen.add(model)

    if request_model in seen:
        seen.remove(request_model)
        remainder = [model for model in ordered if model in seen]
        remainder.sort(reverse=True)
        return [request_model] + remainder
    else:
        ordered_dedup = [model for model in ordered if model in seen]
        ordered_dedup.sort(reverse=True)
        return ordered_dedup

def merge_models(*model_groups):
    merged = []
    seen = set()
    for models in model_groups:
        raw_models = models if isinstance(models, list) else ([models] if models else [])
        for model in raw_models:
            if model and model not in seen:
                merged.append(model)
                seen.add(model)
    return merged

def parse_model_mappings(config):
    raw_mapping = (
        config.get("model_map")
        or config.get("modelMap")
        or config.get("model_mappings")
        or config.get("modelMappings")
    )
    mappings = {}

    if isinstance(raw_mapping, dict):
        for source_model, target_models in raw_mapping.items():
            if source_model:
                mappings[source_model] = merge_models(target_models)
        return mappings

    if isinstance(raw_mapping, list):
        for item in raw_mapping:
            if not isinstance(item, dict):
                continue
            source_model = (
                item.get("from")
                or item.get("source")
                or item.get("request")
                or item.get("model")
            )
            target_models = (
                item.get("to")
                or item.get("target")
                or item.get("targets")
                or item.get("models")
            )
            if source_model:
                mappings[source_model] = merge_models(target_models)
    return mappings

def mapped_model_matches(target_model, available_model):
    return available_model == target_model or available_model.startswith(f"{target_model}-")

def match_mapped_models(mapped_models, available_models):
    matched = []
    seen = set()
    for target_model in mapped_models:
        for available_model in available_models:
            if mapped_model_matches(target_model, available_model) and available_model not in seen:
                matched.append(available_model)
                seen.add(available_model)
    return matched

def match_model_mappings(request_model, channel):
    channel_mappings = parse_model_mappings(channel)
    available_models = merge_models(channel.get("model", []), channel.get("models", []))
    if request_model in channel_mappings:
        return channel_mappings[request_model]

    mapped_models = parse_model_mappings(CONFIG).get(request_model, [])
    return match_mapped_models(mapped_models, available_models)

def is_model_mapping_key(request_model, channel):
    return (
        request_model in parse_model_mappings(channel)
        or request_model in parse_model_mappings(CONFIG)
    )

def upstream_failure_key(request_model, channel_name, upstream_model):
    return (request_model, channel_name, upstream_model)

def mark_upstream_failure(request_model, channel_name, upstream_model, status):
    if status in (401, 402, 403, 410):
        cooldown = 300
    elif status == 429:
        cooldown = 30
    elif status >= 500:
        cooldown = 15
    else:
        cooldown = 5
    key = upstream_failure_key(request_model, channel_name, upstream_model)
    with UPSTREAM_FAILURE_LOCK:
        UPSTREAM_FAILURES[key] = {
            "status": status,
            "until": time.monotonic() + cooldown,
        }

def clear_upstream_failure(request_model, channel_name, upstream_model):
    key = upstream_failure_key(request_model, channel_name, upstream_model)
    with UPSTREAM_FAILURE_LOCK:
        UPSTREAM_FAILURES.pop(key, None)

def select_upstream_attempts(request_model, candidates):
    attempts = [
        (channel, upstream_model)
        for channel in candidates
        for upstream_model in channel["_matched_models"]
    ]
    now = time.monotonic()
    with UPSTREAM_FAILURE_LOCK:
        ready = [
            attempt
            for attempt in attempts
            if UPSTREAM_FAILURES.get(
                upstream_failure_key(request_model, attempt[0]["name"], attempt[1]),
                {"until": 0},
            )["until"] <= now
        ]
        if ready:
            return ready
        return []

def upstream_retry_after(request_model, candidates):
    now = time.monotonic()
    with UPSTREAM_FAILURE_LOCK:
        remaining = [
            UPSTREAM_FAILURES.get(
                upstream_failure_key(request_model, channel["name"], upstream_model),
                {"until": now},
            )["until"] - now
            for channel in candidates
            for upstream_model in channel["_matched_models"]
        ]
    return max(1, int(min((value for value in remaining if value > 0), default=1)))

def match_channels(request_model, req_type):
    candidates = []
    for ch in CONFIG["channels"]:
        # 只跳过负权重渠道；weight 为 0 的渠道仍参与匹配
        if ch.get("weight", 0) < 0:
            continue

        if ch["type"] != req_type:
            continue

        raw_model = ch.get("model", [])
        config_models = (
            raw_model
            if isinstance(raw_model, list)
            else ([raw_model] if raw_model else [])
        )

        if ch.get("default"):
            candidates.clear()
            mapped = match_model_mappings(request_model, ch)
            mapping_key = is_model_mapping_key(request_model, ch)
            model_list = (
                mapped
                if mapping_key
                else merge_models(
                    match_models_in_channel(request_model, config_models),
                    match_models_in_channel(request_model, ch.get("models", [])),
                )
            )
            ch_copy = dict(ch)
            ch_copy["_matched_models"] = model_list
            candidates.append(ch_copy)
            break

        mapped = match_model_mappings(request_model, ch)
        mapping_key = is_model_mapping_key(request_model, ch)
        matched = (
            mapped
            if mapping_key
            else merge_models(
                match_models_in_channel(request_model, config_models),
                match_models_in_channel(request_model, ch.get("models", [])),
            )
        )

        if matched:
            ch_copy = dict(ch)
            ch_copy["_matched_models"] = (
                matched if mapping_key else rank_matched_models(request_model, matched)
            )
            candidates.append(ch_copy)

    candidates.sort(key=lambda x: x.get("weight", 0), reverse=True)

    # 成功缓存逻辑保持不变...
    cached = SUCCESS_CACHE.get(request_model)
    if cached:
        target_ch_name = cached["channel_name"]
        target_model = cached["model"]
        for i, ch in enumerate(candidates):
            if ch["name"] == target_ch_name:
                # 将上次成功的具体模型移到该渠道模型列表的最前面
                match_ch = candidates.pop(i)
                if target_model in match_ch["_matched_models"]:
                    match_ch["_matched_models"].remove(target_model)
                    match_ch["_matched_models"].insert(0, target_model)
                candidates.insert(0, match_ch)
                print(
                    f"Using last cached channel: [{target_ch_name}] for [{request_model}] -> {target_model}"
                )
                break

    print(f"Final ranked candidates for [{request_model}]:")
    for idx, ch in enumerate(candidates, 1):
        print(f"  {idx}. {ch['name']} -> {ch['_matched_models']}")
    return candidates

# 管理台 API：只返回脱敏后的 key，保存时空 key 表示保留原值。
def public_channel(channel):
    result = dict(channel)
    result["apiKeyConfigured"] = bool(channel.get("apiKey"))
    result["apiKey"] = ""
    result.pop("add_headers", None)
    result.pop("modify_headers", None)
    result["proxy"] = ""
    result["proxyInfo"] = public_proxy(channel.get("proxy"))
    result["effectiveProxyInfo"] = public_proxy(effective_proxy(channel))
    return result

@app.route("/admin", methods=["GET"])
def admin_page():
    return render_template("admin.html")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        if not configured_api_keys() or admin_authenticated():
            return redirect(url_for("admin_page"))
        return render_template("login.html", error=None)

    data = request.get_json(silent=True) if request.is_json else request.form
    matched = matching_api_key(str((data or {}).get("apiKey", "")).strip())
    if not matched:
        if request.is_json:
            return jsonify({"error": "Invalid API key"}), 401
        return render_template("login.html", error="API Key 无效"), 401
    session.clear()
    session["apiKeyHash"] = matched["keyHash"]
    session.permanent = True
    target = request.args.get("next", "/admin")
    if not target.startswith("/") or target.startswith("//"):
        target = "/admin"
    if request.is_json:
        return jsonify({"status": "authenticated", "next": target})
    return redirect(target)

@app.route("/admin/logout", methods=["GET", "POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin/security", methods=["GET"])
def admin_security_page():
    return render_template("security.html")

@app.route("/admin/mappings", methods=["GET"])
def admin_mappings_page():
    return render_template("mappings.html")

@app.route("/admin/logs", methods=["GET"])
def admin_logs_page():
    return render_template("logs.html")

@app.route("/admin/api/config", methods=["GET", "PUT"])
def admin_config_api():
    if request.method == "GET":
        return jsonify(
            {
                "listen": CONFIG.get("listen", ""),
                "http2": bool(CONFIG.get("http2", False)),
                "configError": CONFIG_SYNC_ERROR,
                "configMtime": CONFIG_MTIME_NS,
                "configPath": CONFIG_PATH,
                "proxy": "",
                "proxyInfo": public_proxy(CONFIG.get("proxy")),
                "modelMap": parse_model_mappings(CONFIG),
                "channels": [public_channel(channel) for channel in CONFIG.get("channels", [])],
            }
        )

    try:
        data = require_json_object()
        if "listen" in data:
            listen = str(data["listen"]).strip()
            if ":" not in listen:
                raise ValueError("listen must use host:port format")
            CONFIG["listen"] = listen
        if "http2" in data:
            CONFIG["http2"] = bool(data["http2"])
        if "proxy" in data:
            CONFIG["proxy"] = normalize_proxy(data["proxy"], "proxy")
        if "modelMap" in data:
            model_map = data["modelMap"]
            if not isinstance(model_map, dict):
                raise ValueError("modelMap must be an object")
            CONFIG["modelMap"] = [
                {"model": source, "models": targets}
                for source, targets in normalize_model_map(model_map).items()
            ]
        save_config()
        return jsonify({"status": "saved"})
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400

@app.route("/admin/api/security/keys", methods=["GET", "POST"])
def admin_security_keys():
    if request.method == "GET":
        return jsonify(
            {
                "enabled": bool(configured_api_keys()),
                "keys": [
                    {
                        "name": entry.get("name", "Unnamed"),
                        "prefix": entry.get("prefix", ""),
                        "createdAt": entry.get("createdAt"),
                        "enabled": entry.get("enabled", True),
                    }
                    for entry in CONFIG.get("apiKeys", [])
                    if isinstance(entry, dict)
                ],
            }
        )

    try:
        data = require_json_object()
        name = str(data.get("name", "")).strip() or "API Key"
        api_key = str(data.get("key", "")).strip()
        if len(api_key) < 12:
            raise ValueError("API key must contain at least 12 characters")
        key_hash = hash_api_key(api_key)
        if any(
            hmac.compare_digest(entry.get("keyHash", ""), key_hash)
            for entry in CONFIG.get("apiKeys", [])
            if isinstance(entry, dict)
        ):
            raise ValueError("API key already exists")
        entry = {
            "name": name,
            "prefix": api_key[:8],
            "keyHash": key_hash,
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "enabled": True,
        }
        CONFIG.setdefault("apiKeys", []).append(entry)
        session["apiKeyHash"] = key_hash
        session.permanent = True
        save_config()
        return jsonify({"status": "created", "name": name, "prefix": entry["prefix"]}), 201
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400

@app.route("/admin/api/security/keys/<int:index>", methods=["DELETE"])
def admin_security_key_delete(index):
    keys = CONFIG.get("apiKeys", [])
    if index < 0 or index >= len(keys):
        return jsonify({"error": "API key not found"}), 404
    removed = keys.pop(index)
    if session.get("apiKeyHash") == removed.get("keyHash"):
        session.clear()
    save_config()
    return jsonify({"status": "deleted"})

@app.route("/admin/api/channels", methods=["POST"])
def admin_channel_create():
    try:
        channel = normalize_channel(require_json_object())
        if any(existing.get("name") == channel["name"] for existing in CONFIG.get("channels", [])):
            raise ValueError("Channel name already exists")
        CONFIG.setdefault("channels", []).append(channel)
        save_config()
        return jsonify(public_channel(channel)), 201
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400

@app.route("/admin/api/channels/<int:index>", methods=["PUT", "DELETE"])
def admin_channel_detail(index):
    channels = CONFIG.get("channels", [])
    if index < 0 or index >= len(channels):
        return jsonify({"error": "Channel not found"}), 404
    if request.method == "DELETE":
        channels.pop(index)
        save_config()
        return jsonify({"status": "deleted"})

    try:
        updated = normalize_channel(require_json_object(), channels[index])
        if any(i != index and channel.get("name") == updated["name"] for i, channel in enumerate(channels)):
            raise ValueError("Channel name already exists")
        channels[index] = updated
        save_config()
        return jsonify(public_channel(updated))
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400

@app.route("/admin/api/channels/<int:index>/model-map", methods=["PUT"])
def admin_channel_model_map(index):
    channels = CONFIG.get("channels", [])
    if index < 0 or index >= len(channels):
        return jsonify({"error": "Channel not found"}), 404
    try:
        data = require_json_object()
        mappings = normalize_model_map(data.get("modelMap", {}))
        channels[index]["model_map"] = mappings
        for legacy_key in ("modelMap", "model_mappings", "modelMappings"):
            channels[index].pop(legacy_key, None)
        save_config()
        return jsonify({"status": "saved", "modelMap": mappings})
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400

@app.route("/admin/api/logs", methods=["GET", "DELETE"])
def admin_request_logs():
    if request.method == "DELETE":
        with REQUEST_LOG_LOCK:
            REQUEST_LOGS.clear()
            try:
                with open(request_log_path(), "w", encoding="utf-8"):
                    pass
            except OSError as error:
                return jsonify({"error": str(error)}), 500
        return jsonify({"status": "cleared"})

    query = request.args.get("q", "").strip().lower()
    result_filter = request.args.get("result", "all")
    request_type = request.args.get("type", "all")
    try:
        limit = min(500, max(1, int(request.args.get("limit", 200))))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400

    with REQUEST_LOG_LOCK:
        all_logs = list(reversed(REQUEST_LOGS))
    filtered = []
    for entry in all_logs:
        if result_filter == "success" and entry.get("status", 500) >= 400:
            continue
        if result_filter == "error" and entry.get("status", 0) < 400:
            continue
        if request_type != "all" and entry.get("requestType") != request_type:
            continue
        if query and query not in " ".join(
            str(entry.get(field, ""))
            for field in ("requestModel", "upstreamModel", "channel", "route", "error")
        ).lower():
            continue
        filtered.append(entry)
        if len(filtered) >= limit:
            break
    return jsonify(
        {
            "logs": filtered,
            "total": len(all_logs),
            "success": sum(1 for entry in all_logs if entry.get("status", 500) < 400),
            "error": sum(1 for entry in all_logs if entry.get("status", 0) >= 400),
        }
    )

def refresh_channel_models(channel):
    base_url = channel["baseUrl"].rstrip("/")
    target_urls = [f"{base_url}/v1/models"]
    path_parts = base_url.split("/")
    if len(path_parts) > 3:
        parent_url = "/".join(path_parts[:-1]) + "/v1/models"
        if parent_url not in target_urls:
            target_urls.append(parent_url)

    headers = {"Authorization": f"Bearer {channel.get('apiKey', '')}"}
    last_error = "No models returned"
    for url in target_urls:
        try:
            response = httpx.get(
                url,
                headers=headers,
                timeout=10,
                verify=False,
                follow_redirects=True,
                proxy=effective_proxy(channel),
            )
            if response.status_code != 200:
                last_error = f"{url} returned HTTP {response.status_code}"
                continue
            models = [item["id"] for item in response.json().get("data", []) if item.get("id")]
            if not models:
                last_error = f"{url} returned no models"
                continue
            channel["models"] = merge_models(models)
            if channel.get("weight", 0) < 0:
                channel["weight"] = abs(channel["weight"])
            print(f"Updated models for {channel['name']} via {url}")
            return True, url
        except Exception as error:
            last_error = str(error)

    if channel.get("weight", 0) > 0:
        channel["weight"] *= -1
    print(f"Failed to update models for {channel['name']}: {last_error}")
    return False, last_error

@app.route("/admin/api/channels/<int:index>/refresh-models", methods=["POST"])
def admin_channel_refresh_models(index):
    channels = CONFIG.get("channels", [])
    if index < 0 or index >= len(channels):
        return jsonify({"error": "Channel not found"}), 404

    success, detail = refresh_channel_models(channels[index])
    save_config()
    if not success:
        return jsonify({"error": detail, "channel": public_channel(channels[index])}), 502
    return jsonify(
        {
            "status": "updated",
            "source": detail,
            "channel": public_channel(channels[index]),
        }
    )

def run_model_refresh_job(job_id, indices):
    def refresh_one(index):
        channels = CONFIG.get("channels", [])
        if index >= len(channels):
            return index, False, "Channel not found", None
        success, detail = refresh_channel_models(channels[index])
        save_config()
        return index, success, detail, public_channel(channels[index])

    with ThreadPoolExecutor(max_workers=min(3, len(indices) or 1)) as executor:
        futures = {executor.submit(refresh_one, index): index for index in indices}
        for future in as_completed(futures):
            index = futures[future]
            try:
                index, success, detail, channel = future.result()
            except Exception as error:
                success, detail, channel = False, str(error), None
            with MODEL_REFRESH_LOCK:
                job = MODEL_REFRESH_JOBS[job_id]
                job["done"] += 1
                job["success"] += int(success)
                job["failed"] += int(not success)
                job["results"].append(
                    {"index": index, "success": success, "detail": detail, "channel": channel}
                )
    with MODEL_REFRESH_LOCK:
        MODEL_REFRESH_JOBS[job_id]["status"] = "completed"

@app.route("/admin/api/model-refresh-jobs", methods=["POST"])
def admin_model_refresh_jobs_create():
    data = request.get_json(silent=True) or {}
    indices = data.get("indices")
    if indices is None:
        indices = list(range(len(CONFIG.get("channels", []))))
    if not isinstance(indices, list) or any(not isinstance(index, int) for index in indices):
        return jsonify({"error": "indices must be a list of integers"}), 400
    indices = list(dict.fromkeys(index for index in indices if 0 <= index < len(CONFIG.get("channels", []))))
    job_id = uuid4().hex
    with MODEL_REFRESH_LOCK:
        MODEL_REFRESH_JOBS[job_id] = {
            "id": job_id,
            "status": "running",
            "total": len(indices),
            "done": 0,
            "success": 0,
            "failed": 0,
            "results": [],
        }
    threading.Thread(target=run_model_refresh_job, args=(job_id, indices), daemon=True).start()
    return jsonify(copy.deepcopy(MODEL_REFRESH_JOBS[job_id])), 202

@app.route("/admin/api/model-refresh-jobs/<job_id>", methods=["GET"])
def admin_model_refresh_jobs_detail(job_id):
    with MODEL_REFRESH_LOCK:
        job = MODEL_REFRESH_JOBS.get(job_id)
        if not job:
            return jsonify({"error": "Refresh job not found"}), 404
        return jsonify(copy.deepcopy(job))

# 功能1：导入功能 访问示例：/providers/api-keys?v=1&data=ey...
@app.route("/providers/api-keys", methods=["GET"])
def import_handler():
    # raw_url = request.args.get("url")
    raw_url = request.url
    if not raw_url or "data=" not in raw_url:
        return jsonify({"error": "Invalid import URL"}), 400

    try:
        # 解析参数
        parsed = urlparse(raw_url)
        params = parse_qs(parsed.query)
        # 需要取第一个元素
        v_type = params.get("v", [None])[0]  # 获取列表第一个元素，默认为 None
        data_b64 = params.get("data", [None])[0]

        if not data_b64:
            raise ValueError("缺少 data 参数")

        # Base64 解码 (补全填充，还原被URL解码的+号)
        data_b64 = data_b64.replace(" ", "+")
        missing_padding = len(data_b64) % 4
        if missing_padding:
            data_b64 += "=" * (4 - missing_padding)

        decoded_data = json.loads(base64.b64decode(data_b64).decode("utf-8"))

        # 提取要导入的配置信息
        import_base_url = decoded_data.get("baseUrl", "")
        import_api_key = decoded_data.get("apiKey", "")
        import_name = decoded_data.get("name", "Imported")

        # 映射类型: 1=codex, 2=cc, 3=Gemini, 4=oai兼容
        type_map = {
            "1": "openai-responses",
            "2": "claude",
            "3": "gemini",
            "4": "openai-chat",
        }
        target_type = type_map.get(v_type or "", "openai-chat")

        # 重复判断：检查是否已存在相同的 baseUrl、apiKey 和 type
        existing_channels = CONFIG.get("channels", [])
        for channel in existing_channels:
            # 标准化比较（去除末尾斜杠，统一小写）
            existing_url = channel.get("baseUrl", "").rstrip("/").lower()
            existing_key = channel.get("apiKey", "")
            import_url_clean = import_base_url.rstrip("/").lower()
            if (
                existing_url == import_url_clean
                and existing_key == import_api_key
                and channel.get("type") == target_type
            ):
                return jsonify(
                    {
                        "status": "skipped",
                        "message": f"Channel already exists: {channel.get('name', 'Unknown')}",
                        "existing": channel.get("name"),
                    }
                ), 200

        # 名称加type后缀，避免同名冲突
        type_suffix = {
            "openai-responses": "_codex",
            "claude": "_cc",
            "gemini": "_gemini",
            "openai-chat": "_oai",
        }
        suffix = type_suffix.get(target_type, "")
        if suffix and not import_name.endswith(suffix):
            import_name = import_name + suffix

        # 名称重复判断
        for channel in existing_channels:
            if channel.get("name") == import_name:
                return jsonify(
                    {
                        "status": "skipped",
                        "message": f"Channel already exists: {import_name}",
                    }
                ), 200

        # 模版构造
        new_channel = {
            "name": import_name,
            "type": target_type,
            "baseUrl": import_base_url,
            "apiKey": import_api_key,
            "website": "",
            "remark": "",
            "weight": 11,
            "interval": 6,
            "timeout": 66,
            "model": ["gpt-5.5"],  # 默认占位
            "model_map": {},
            "models": [],
            "default": False,
            "add_headers": {},
            "modify_headers": {},
            "remove_headers": [],
        }

        CONFIG["channels"].append(new_channel)
        save_config()
        return jsonify({"status": "success", "added": new_channel["name"]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 功能2：增强 Models 接口
@app.route("/v1/models", methods=["GET"])
def openai_models_entry():
    is_update = request.args.get("u") == "1"

    if is_update:
        for ch in CONFIG["channels"]:
            refresh_channel_models(ch)

        save_config()  # 落地文件
        # CONFIG 已在内存中更新，无需重新 load_config

    # 返回聚合的模型列表
    model_lists = set(parse_model_mappings(CONFIG).keys())
    for ch in CONFIG["channels"]:
        if ch.get("weight", 0) >= 0:
            model_lists.update(ch.get("models", []))
            model_lists.update(merge_models(ch.get("model", [])))
            model_lists.update(parse_model_mappings(ch).keys())

    return jsonify({"data": [{"id": m, "object": "model"} for m in model_lists]})

# 转发逻辑
SUCCESS_CACHE = {}

def build_headers(orig, channel):
    remove_set = {h.lower() for h in channel.get("remove_headers", [])}
    headers = {}
    for k, v in orig.items():
        lower_k = k.lower()
        # 不透传来路认证头，避免 httpx 把不同大小写的旧 token 一起发给上游。
        if (
            lower_k in remove_set
            or lower_k in AUTH_HEADER_NAMES
            or lower_k in ("host", "content-length", "accept-encoding")
        ):
            continue
        headers[k] = v
    for k, v in channel.get("modify_headers", {}).items():
        headers[k] = v
    for k, v in channel.get("add_headers", {}).items():
        headers[k] = v
    if not any(k.lower() == "accept-encoding" for k in headers):
        headers["Accept-Encoding"] = "identity"
    headers["Authorization"] = f"Bearer {channel.get('apiKey')}"
    if channel["type"] == "claude":
        headers["x-api-key"] = channel.get("apiKey")
    if channel["type"] == "gemini":
        headers["x-goog-api-key"] = channel.get("apiKey")
    headers["Content-Type"] = "application/json"
    return headers

def build_url(channel, route_path=None):
    base = channel["baseUrl"].rstrip("/")
    # 如果传入route_path且包含#，使用#前的完整路径
    if route_path and "#" in route_path:
        route_path = route_path.split("#")[0]
        return base + route_path
    if channel["type"] == "claude":
        return (
            base + "/v1/messages?beta=true"
            if "beta=true" not in request.full_path
            else base + request.full_path
        )
    elif channel["type"] == "openai-chat":
        return base + "/v1/chat/completions"
    elif channel["type"] == "openai-responses":
        return base + "/v1/responses"
    elif channel["type"] == "gemini":
        return base + "/v1/chat/completions"
    # 多模态路由：直接使用传入的route_path
    if route_path:
        return base + route_path
    return base

def wait_times(ch):
    interval = ch.get("interval", 0)
    if interval > 0:
        print(f"Waiting {interval}s before retrying channel: {ch['name']}")
        time.sleep(interval)

def build_upstream_timeout(channel, body_size):
    base = max(1.0, float(channel.get("timeout", 20)))
    size_mb = max(0, body_size) / (1024 * 1024)
    connect_timeout = float(channel.get("connectTimeout", min(30, max(10, base / 3))))
    write_timeout = float(
        channel.get("writeTimeout", min(600, max(30, base) + size_mb * 20))
    )
    read_timeout = float(
        channel.get("readTimeout", min(900, base + size_mb * 25))
    )
    pool_timeout = float(channel.get("poolTimeout", min(60, max(10, base / 2))))
    return httpx.Timeout(
        connect=connect_timeout,
        write=write_timeout,
        read=read_timeout,
        pool=pool_timeout,
    )

def forward(payload, req_type, route_path=None):
    original_model = payload.get("model", "")
    stream = payload.get("stream", False)
    body_size = request.content_length
    if body_size is None:
        body_size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    candidates = match_channels(original_model, req_type)

    if not candidates:
        record_request_log(original_model, req_type, None, None, 400, time.monotonic(), "No channel matched", stream)
        return jsonify({"error": "No channel matched"}), 400

    last_error = None
    last_response = None
    selected = select_upstream_attempts(original_model, candidates)
    if not selected:
        retry_after = upstream_retry_after(original_model, candidates)
        return jsonify(
            {
                "error": "All matching upstreams are cooling down",
                "retryAfter": retry_after,
            }
        ), 503, {"Retry-After": str(retry_after)}
    selected_attempts = {
        (channel["name"], upstream_model)
        for channel, upstream_model in selected
    }
    previous_channel = None
    for ch in candidates:
        for candidate_model in ch["_matched_models"]:
            if (ch["name"], candidate_model) not in selected_attempts:
                continue
            print()
            started_at = time.monotonic()
            if previous_channel == ch["name"]:
                wait_times(ch)
            previous_channel = ch["name"]
            try:
                body = dict(payload)
                body["model"] = candidate_model
                print(f"Requesting -> Channel: {ch['name']}, Model: {candidate_model}")
                headers = build_headers(request.headers, ch)
                url = build_url(ch, route_path)
                timeout = build_upstream_timeout(ch, body_size)
                client = httpx.Client(
                    http2=ch.get("http2", False),
                    verify=False,
                    timeout=timeout,
                    proxy=effective_proxy(ch),
                )
                if stream:
                    req = client.stream("POST", url, headers=headers, json=body)
                    resp = req.__enter__()
                    # print("resp: ", resp)
                    if resp.status_code < 400:
                        clear_upstream_failure(original_model, ch["name"], candidate_model)
                        SUCCESS_CACHE[original_model] = {
                            "channel_name": ch["name"],
                            "model": candidate_model,
                        }

                        request_route = request.path

                        def generate(resp, req, client):
                            response_bytes = 0
                            stream_error = None
                            try:
                                for chunk in resp.iter_bytes():
                                    if chunk:
                                        response_bytes += len(chunk)
                                        yield chunk
                            except httpx.HTTPError as e:
                                stream_error = str(e)
                                print(
                                    f"Stream error: {ch['name']} -> {candidate_model} -> {e}"
                                )
                                mark_upstream_failure(original_model, ch["name"], candidate_model, 599)
                                if original_model in SUCCESS_CACHE:
                                    del SUCCESS_CACHE[original_model]
                            finally:
                                record_request_log(
                                    original_model,
                                    req_type,
                                    ch["name"],
                                    candidate_model,
                                    resp.status_code,
                                    started_at,
                                    stream_error,
                                    stream=True,
                                    response_bytes=response_bytes,
                                    route=request_route,
                                )
                                req.__exit__(None, None, None)
                                client.close()

                        headers_out = {
                            "Content-Type": "text/event-stream",
                            "Cache-Control": "no-cache",
                            "Connection": "keep-alive",
                        }

                        r = Response(
                            generate(resp, req, client),
                            status=resp.status_code,
                            content_type=resp.headers.get("content-type"),
                            headers=headers_out,
                        )
                        # print("resp: ", r.data)
                        return r
                    else:
                        resp.read()
                        last_response = (
                            resp.status_code,
                            resp.content,
                            resp.headers.get("content-type"),
                        )
                        req.__exit__(None, None, None)
                        client.close()
                        print(
                            "Channel Model failed: {} -> {} -> {}".format(
                                ch["name"], candidate_model, resp.text[:200]
                            )
                        )
                        mark_upstream_failure(original_model, ch["name"], candidate_model, resp.status_code)
                        record_request_log(original_model, req_type, ch["name"], candidate_model, resp.status_code, started_at, resp.text, stream=stream, response_bytes=len(resp.content))
                        if original_model in SUCCESS_CACHE:
                            print(f"Cache cleared for {original_model} due to failure.")
                            del SUCCESS_CACHE[original_model]
                        continue
                else:
                    resp = client.post(url, headers=headers, json=body)
                    client.close()

                    if resp.status_code < 400:
                        clear_upstream_failure(original_model, ch["name"], candidate_model)
                        record_request_log(original_model, req_type, ch["name"], candidate_model, resp.status_code, started_at, stream=stream, response_bytes=len(resp.content))
                        SUCCESS_CACHE[original_model] = {
                            "channel_name": ch["name"],
                            "model": candidate_model,
                        }
                        return Response(
                            resp.content,
                            status=resp.status_code,
                            content_type=resp.headers.get("content-type"),
                        )

                    # 如果失败（4xx 或 5xx）
                    print(
                        "Channel Model failed: {} -> {} -> {}".format(
                            ch["name"], candidate_model, resp.text
                        )
                    )
                    last_response = (
                        resp.status_code,
                        resp.content,
                        resp.headers.get("content-type"),
                    )
                    mark_upstream_failure(original_model, ch["name"], candidate_model, resp.status_code)
                    record_request_log(original_model, req_type, ch["name"], candidate_model, resp.status_code, started_at, resp.text, stream=stream, response_bytes=len(resp.content))

                # 🔥 关键：只要当前尝试的模型失败了，就清除缓存，确保下次请求会重新遍历
                if original_model in SUCCESS_CACHE:
                    print(f"Cache cleared for {original_model} due to failure.")
                    del SUCCESS_CACHE[original_model]
            except Exception as e:
                last_error = str(e)
                mark_upstream_failure(original_model, ch["name"], candidate_model, 599)
                record_request_log(original_model, req_type, ch["name"], candidate_model, 599, started_at, last_error, stream=stream)
                if original_model in SUCCESS_CACHE:
                    del SUCCESS_CACHE[original_model]
                print("Error:", last_error)
                # wait_times(ch)
                continue
    if last_response:
        status, content, content_type = last_response
        return Response(content, status=status, content_type=content_type)
    status = 504 if last_error and "timed out" in last_error.lower() else 502
    return jsonify({"error": "All channels failed", "detail": last_error}), status

@app.route("/v1/messages", methods=["POST"])
def claude_entry():
    return forward(request.json, "claude")

@app.route("/v1/chat/completions", methods=["POST"])
def openai_chat_entry():
    return forward(request.json, "openai-chat")

@app.route("/v1/responses", methods=["POST"])
def openai_responses_entry():
    return forward(request.json, "openai-responses")

# ====================================
# 多模态 API 接口
# ====================================
@app.route("/v1/images/generations", methods=["POST"])
def images_generations_entry():
    return forward(request.json, "openai-chat", "/v1/images/generations")

@app.route("/v1/images/edits", methods=["POST"])
def images_edits_entry():
    return forward(request.json, "openai-chat", "/v1/images/edits")

@app.route("/v1/audio/speech", methods=["POST"])
def audio_speech_entry():
    return forward(request.json, "openai-chat", "/v1/audio/speech")

@app.route("/v1/audio/transcriptions", methods=["POST"])
def audio_transcriptions_entry():
    return forward(request.json, "openai-chat", "/v1/audio/transcriptions")

@app.route("/v1/audio/translations", methods=["POST"])
def audio_translations_entry():
    return forward(request.json, "openai-chat", "/v1/audio/translations")

@app.route("/v1/embeddings", methods=["POST"])
def embeddings_entry():
    return forward(request.json, "openai-chat", "/v1/embeddings")

@app.route("/v1/rerank", methods=["POST"])
def rerank_entry():
    return forward(request.json, "openai-chat", "/v1/rerank")

@app.route("/v1/completions", methods=["POST"])
def completions_entry():
    return forward(request.json, "openai-chat", "/v1/completions")

@app.route("/v1/moderations", methods=["POST"])
def moderations_entry():
    return forward(request.json, "openai-chat", "/v1/moderations")

def main():
    global CONFIG, CONFIG_MTIME_NS, CONFIG_FILE_STATE
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.json")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload on code changes")
    args = parser.parse_args()
    globals()["CONFIG_PATH"] = os.path.abspath(args.config)
    CONFIG = load_config(CONFIG_PATH)
    CONFIG_FILE_STATE = config_file_state()
    CONFIG_MTIME_NS = CONFIG_FILE_STATE[2]
    if CONFIG.get("adminSessionSecret"):
        app.secret_key = CONFIG["adminSessionSecret"]
    else:
        CONFIG["adminSessionSecret"] = app.secret_key
        save_config()
    load_request_logs()
    start_config_watcher()

    host, port = CONFIG["listen"].split(":")
    print(f"Proxy running on {host}:{port}")
    print(f"Loaded {len(CONFIG['channels'])} channels")
    app.run(host=host, port=int(port), threaded=True, use_reloader=args.reload)

if __name__ == "__main__":
    main()
