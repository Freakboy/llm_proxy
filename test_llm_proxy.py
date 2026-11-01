import unittest
from unittest.mock import Mock, patch
import json
import os
import tempfile

import llm_proxy


class MatchChannelsTest(unittest.TestCase):
    def setUp(self):
        llm_proxy.SUCCESS_CACHE.clear()
        llm_proxy.UPSTREAM_FAILURES.clear()
        llm_proxy.CONFIG.clear()

    def test_global_mapping_only_matches_channels_with_mapped_models(self):
        llm_proxy.CONFIG.update(
            {
                "modelMap": [
                    {
                        "model": "glm-new",
                        "models": ["glm-5.3", "z-ai/glm-5.3"],
                    }
                ],
                "channels": [
                    {
                        "name": "old-only",
                        "type": "openai-chat",
                        "weight": 20,
                        "model": ["glm-5.2"],
                        "models": ["z-ai/glm-5.2"],
                    },
                    {
                        "name": "supports-new",
                        "type": "openai-chat",
                        "weight": 10,
                        "model": ["glm-5.2"],
                        "models": ["z-ai/glm-5.3"],
                    },
                ],
            }
        )

        candidates = llm_proxy.match_channels("glm-new", "openai-chat")

        self.assertEqual([candidate["name"] for candidate in candidates], ["supports-new"])
        self.assertEqual(candidates[0]["_matched_models"], ["z-ai/glm-5.3"])

    def test_channel_mapping_is_an_explicit_override(self):
        llm_proxy.CONFIG.update(
            {
                "modelMap": [
                    {
                        "model": "glm-new",
                        "models": ["glm-5.3"],
                    }
                ],
                "channels": [
                    {
                        "name": "explicit-map",
                        "type": "openai-chat",
                        "weight": 10,
                        "model": [],
                        "models": [],
                        "model_map": {"glm-new": "provider/glm-next"},
                    }
                ],
            }
        )

        candidates = llm_proxy.match_channels("glm-new", "openai-chat")

        self.assertEqual([candidate["name"] for candidate in candidates], ["explicit-map"])
        self.assertEqual(candidates[0]["_matched_models"], ["provider/glm-next"])

    def test_mapping_key_does_not_fall_back_to_fuzzy_model_match(self):
        llm_proxy.CONFIG.update(
            {
                "modelMap": {"glm": ["glm-5.2"]},
                "channels": [
                    {
                        "name": "only-new",
                        "type": "openai-chat",
                        "weight": 10,
                        "model": ["glm-5.3"],
                        "models": ["glm-5.3"],
                    },
                    {
                        "name": "mapped-target",
                        "type": "openai-chat",
                        "weight": 5,
                        "model": ["glm-5.2"],
                        "models": ["glm-5.2", "glm-5.3"],
                    },
                ],
            }
        )

        candidates = llm_proxy.match_channels("glm", "openai-chat")

        self.assertEqual([candidate["name"] for candidate in candidates], ["mapped-target"])
        self.assertEqual(candidates[0]["_matched_models"], ["glm-5.2"])

    def test_mapping_target_matches_same_family_suffix_models(self):
        llm_proxy.CONFIG.update(
            {
                "modelMap": {"glm": ["glm-5.2"]},
                "channels": [
                    {
                        "name": "long-context",
                        "type": "openai-chat",
                        "weight": 10,
                        "model": [],
                        "models": ["glm-5.2-200k"],
                    }
                ],
            }
        )

        candidates = llm_proxy.match_channels("glm", "openai-chat")

        self.assertEqual([candidate["name"] for candidate in candidates], ["long-context"])
        self.assertEqual(candidates[0]["_matched_models"], ["glm-5.2-200k"])

    def test_mapping_target_suffix_family_does_not_match_adjacent_version(self):
        llm_proxy.CONFIG.update(
            {
                "modelMap": {"glm": ["glm-5.2"]},
                "channels": [
                    {
                        "name": "wrong-version",
                        "type": "openai-chat",
                        "weight": 10,
                        "model": [],
                        "models": ["glm-5.20"],
                    }
                ],
            }
        )

        candidates = llm_proxy.match_channels("glm", "openai-chat")

        self.assertEqual(candidates, [])


class AdminApiTest(unittest.TestCase):
    def setUp(self):
        llm_proxy.SUCCESS_CACHE.clear()
        llm_proxy.UPSTREAM_FAILURES.clear()
        llm_proxy.CONFIG.clear()
        llm_proxy.CONFIG.update(
            {
                "listen": "127.0.0.1:3838",
                "http2": False,
                "modelMap": [],
                "channels": [
                    {
                        "name": "demo",
                        "type": "openai-chat",
                        "baseUrl": "https://example.com/v1",
                        "apiKey": "secret-token",
                        "weight": 1,
                        "interval": 0,
                        "timeout": 20,
                        "model": ["demo-model"],
                        "models": [],
                        "default": False,
                        "model_map": {},
                        "add_headers": {"Authorization": "another-secret"},
                        "modify_headers": {"x-api-key": "header-secret"},
                        "remove_headers": [],
                    }
                ],
            }
        )
        self.temp_dir = tempfile.TemporaryDirectory()
        llm_proxy.CONFIG_PATH = os.path.join(self.temp_dir.name, "config.json")
        llm_proxy.CONFIG_MTIME_NS = None
        llm_proxy.CONFIG_FILE_STATE = None
        llm_proxy.CONFIG_FAILED_STATE = None
        llm_proxy.CONFIG_SYNC_ERROR = None
        llm_proxy.REQUEST_LOGS.clear()
        self.client = llm_proxy.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_config_get_redacts_api_key(self):
        response = self.client.get("/admin/api/config")

        self.assertEqual(response.status_code, 200)
        channel = response.get_json()["channels"][0]
        self.assertEqual(channel["apiKey"], "")
        self.assertTrue(channel["apiKeyConfigured"])
        self.assertNotIn("add_headers", channel)
        self.assertNotIn("modify_headers", channel)

    def test_proxy_configuration_is_redacted_but_effective_proxy_is_available(self):
        llm_proxy.CONFIG["proxy"] = "http://user:secret@example-proxy:8080"
        llm_proxy.CONFIG["channels"][0]["proxy"] = "socks5://channel-user:secret@channel-proxy:1080"

        response = self.client.get("/admin/api/config")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["proxy"], "")
        self.assertEqual(data["proxyInfo"], {"configured": True, "display": "http://example-proxy:8080"})
        self.assertEqual(data["channels"][0]["proxy"], "")
        self.assertEqual(
            data["channels"][0]["effectiveProxyInfo"],
            {"configured": True, "display": "socks5://channel-proxy:1080"},
        )

    def test_channel_proxy_overrides_global_proxy(self):
        llm_proxy.CONFIG["proxy"] = "http://global-proxy:8080"
        llm_proxy.CONFIG["channels"][0]["proxy"] = "http://channel-proxy:8080"

        self.assertEqual(
            llm_proxy.effective_proxy(llm_proxy.CONFIG["channels"][0]),
            "http://channel-proxy:8080",
        )

    def test_external_config_file_change_reloads_before_request(self):
        llm_proxy.save_config()
        previous_mtime = llm_proxy.CONFIG_MTIME_NS
        external_config = dict(llm_proxy.CONFIG)
        external_config["channels"] = [dict(llm_proxy.CONFIG["channels"][0], name="from-file")]
        with open(llm_proxy.CONFIG_PATH, "w", encoding="utf-8") as config_file:
            json.dump(external_config, config_file)
        os.utime(
            llm_proxy.CONFIG_PATH,
            ns=(previous_mtime + 1_000_000, previous_mtime + 1_000_000),
        )

        response = self.client.get("/admin/api/config")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["channels"][0]["name"], "from-file")
        self.assertEqual(llm_proxy.CONFIG["channels"][0]["name"], "from-file")

    def test_config_watcher_reloads_without_http_request(self):
        llm_proxy.save_config()
        external_config = dict(llm_proxy.CONFIG)
        external_config["channels"] = [dict(llm_proxy.CONFIG["channels"][0], name="watched-file")]
        stop_event = llm_proxy.threading.Event()
        watcher = llm_proxy.threading.Thread(
            target=llm_proxy.config_watch_loop,
            args=(stop_event,),
            daemon=True,
        )
        watcher.start()
        with open(llm_proxy.CONFIG_PATH, "w", encoding="utf-8") as config_file:
            json.dump(external_config, config_file)

        for _ in range(30):
            if llm_proxy.CONFIG["channels"][0]["name"] == "watched-file":
                break
            llm_proxy.time.sleep(0.05)
        stop_event.set()
        watcher.join(timeout=2)

        self.assertEqual(llm_proxy.CONFIG["channels"][0]["name"], "watched-file")

    def test_channel_update_with_empty_key_preserves_existing_key(self):
        response = self.client.put(
            "/admin/api/channels/0",
            json={
                "name": "demo-renamed",
                "type": "openai-chat",
                "baseUrl": "https://example.com/v1",
                "apiKey": "",
                "weight": 8,
                "model": ["glm-5.3"],
                "models": ["glm-5.3"],
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(llm_proxy.CONFIG["channels"][0]["apiKey"], "secret-token")
        self.assertEqual(llm_proxy.CONFIG["channels"][0]["weight"], 8)
        self.assertEqual(llm_proxy.CONFIG["channels"][0]["model"], ["glm-5.3"])
        with open(llm_proxy.CONFIG_PATH, "r", encoding="utf-8") as config_file:
            saved = json.load(config_file)
        self.assertEqual(saved["channels"][0]["name"], "demo-renamed")
        self.assertEqual(saved["channels"][0]["weight"], 8)

    def test_channel_model_map_can_be_saved_separately(self):
        response = self.client.put(
            "/admin/api/channels/0/model-map",
            json={"modelMap": {"glm-new": ["provider/glm-5.3"]}},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            llm_proxy.CONFIG["channels"][0]["model_map"],
            {"glm-new": ["provider/glm-5.3"]},
        )

    def test_request_logs_can_be_filtered_and_cleared(self):
        full_error = "upstream failed\n" + "error detail " * 300
        with llm_proxy.app.test_request_context("/v1/chat/completions"):
            llm_proxy.record_request_log(
                "glm-new",
                "openai-chat",
                "demo",
                "provider/glm-5.3",
                200,
                llm_proxy.time.monotonic(),
            )
            llm_proxy.record_request_log(
                "bad-model",
                "openai-chat",
                "demo",
                "bad-model",
                500,
                llm_proxy.time.monotonic(),
                full_error,
            )

        response = self.client.get("/admin/api/logs?result=error&q=bad-model")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(len(data["logs"]), 1)
        self.assertEqual(data["logs"][0]["status"], 500)
        self.assertEqual(data["logs"][0]["error"], full_error)
        self.assertNotIn("prompt", data["logs"][0])

        clear_response = self.client.delete("/admin/api/logs")
        self.assertEqual(clear_response.status_code, 200)
        self.assertEqual(len(llm_proxy.REQUEST_LOGS), 0)

    def test_admin_multi_page_routes_load(self):
        self.assertEqual(self.client.get("/admin").status_code, 200)
        self.assertEqual(self.client.get("/admin/mappings").status_code, 200)
        self.assertEqual(self.client.get("/admin/logs").status_code, 200)
        self.assertEqual(self.client.get("/admin/security").status_code, 200)

    def test_first_api_key_is_hashed_and_automatically_logs_in_admin(self):
        response = self.client.post(
            "/admin/api/security/keys",
            json={"name": "test-client", "key": "llmp_test_secret_123456"},
        )

        self.assertEqual(response.status_code, 201)
        stored = llm_proxy.CONFIG["apiKeys"][0]
        self.assertNotEqual(stored["keyHash"], "llmp_test_secret_123456")
        self.assertNotIn("llmp_test_secret_123456", json.dumps(llm_proxy.CONFIG))
        self.assertEqual(self.client.get("/admin").status_code, 200)

    def test_configured_api_key_protects_v1_and_admin_routes(self):
        api_key = "llmp_test_secret_123456"
        llm_proxy.CONFIG["apiKeys"] = [
            {
                "name": "test",
                "prefix": api_key[:8],
                "keyHash": llm_proxy.hash_api_key(api_key),
                "enabled": True,
            }
        ]
        anonymous = llm_proxy.app.test_client()

        self.assertEqual(anonymous.get("/v1/models").status_code, 401)
        self.assertEqual(anonymous.get("/admin").status_code, 302)
        self.assertEqual(anonymous.get("/admin/api/config").status_code, 401)
        self.assertEqual(
            anonymous.get(
                "/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            ).status_code,
            200,
        )
        self.assertEqual(
            anonymous.get("/v1/models", headers={"x-api-key": api_key}).status_code,
            200,
        )

    def test_shared_api_key_can_log_in_to_admin(self):
        api_key = "llmp_test_secret_123456"
        llm_proxy.CONFIG["apiKeys"] = [
            {
                "name": "admin",
                "prefix": api_key[:8],
                "keyHash": llm_proxy.hash_api_key(api_key),
                "enabled": True,
            }
        ]
        browser = llm_proxy.app.test_client()

        failed = browser.post("/admin/login", data={"apiKey": "wrong-key-value"})
        success = browser.post("/admin/login", data={"apiKey": api_key})

        self.assertEqual(failed.status_code, 401)
        self.assertEqual(success.status_code, 302)
        self.assertEqual(browser.get("/admin").status_code, 200)

    def test_ai_tool_api_key_header_and_query_formats_are_supported(self):
        api_key = "llmp_test_secret_123456"
        llm_proxy.CONFIG["apiKeys"] = [
            {
                "name": "tool",
                "prefix": api_key[:8],
                "keyHash": llm_proxy.hash_api_key(api_key),
                "enabled": True,
            }
        ]
        client = llm_proxy.app.test_client()

        self.assertEqual(client.get("/v1/models", headers={"Authorization": api_key}).status_code, 200)
        self.assertEqual(client.get("/v1/models", headers={"x-goog-api-key": api_key}).status_code, 200)
        self.assertEqual(client.get(f"/v1/models?key={api_key}").status_code, 200)
        self.assertEqual(client.get(f"/v1/models?api_key={api_key}").status_code, 200)

    def test_auth_failure_log_records_source_without_full_key(self):
        valid_key = "llmp_valid_secret_123456"
        invalid_key = "llmp_invalid_secret_654321"
        llm_proxy.CONFIG["apiKeys"] = [
            {
                "name": "tool",
                "prefix": valid_key[:8],
                "keyHash": llm_proxy.hash_api_key(valid_key),
                "enabled": True,
            }
        ]

        response = llm_proxy.app.test_client().get(
            "/v1/models",
            headers={"x-goog-api-key": invalid_key},
        )

        self.assertEqual(response.status_code, 401)
        entry = llm_proxy.REQUEST_LOGS[-1]
        self.assertEqual(entry["status"], 401)
        self.assertIn("source=x-goog-api-key", entry["error"])
        self.assertNotIn(invalid_key, json.dumps(entry))

    @patch("llm_proxy.httpx.Client")
    def test_request_log_records_non_stream_response_length(self, client_class):
        content = b'{"answer":"hello"}'
        upstream = Mock(
            status_code=200,
            content=content,
            text=content.decode(),
            headers={"content-type": "application/json"},
        )
        client_class.return_value.post.return_value = upstream

        response = self.client.post(
            "/v1/chat/completions",
            json={"model": "demo-model", "messages": []},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(llm_proxy.REQUEST_LOGS[-1]["responseBytes"], len(content))

    @patch("llm_proxy.httpx.get")
    def test_refresh_models_updates_list_and_restores_negative_weight(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {"data": [{"id": "glm-5.3"}, {"id": "glm-5.3"}, {"id": "z-ai/glm-5.3"}]}
        get.return_value = response
        llm_proxy.CONFIG["channels"][0]["weight"] = -7

        result = self.client.post("/admin/api/channels/0/refresh-models")

        self.assertEqual(result.status_code, 200)
        self.assertEqual(llm_proxy.CONFIG["channels"][0]["models"], ["glm-5.3", "z-ai/glm-5.3"])
        self.assertEqual(llm_proxy.CONFIG["channels"][0]["weight"], 7)
        get.assert_called_once()

    @patch("llm_proxy.httpx.get")
    def test_model_refresh_uses_effective_proxy(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {"data": [{"id": "proxy-model"}]}
        get.return_value = response
        llm_proxy.CONFIG["proxy"] = "http://global-proxy:8080"
        llm_proxy.CONFIG["channels"][0]["proxy"] = "http://channel-proxy:8080"

        result = self.client.post("/admin/api/channels/0/refresh-models")

        self.assertEqual(result.status_code, 200)
        self.assertEqual(get.call_args.kwargs["proxy"], "http://channel-proxy:8080")

    @patch("llm_proxy.httpx.Client")
    def test_forward_uses_global_proxy_when_channel_proxy_is_empty(self, client_class):
        upstream = Mock(
            status_code=200,
            content=b'{"ok":true}',
            text='{"ok":true}',
            headers={"content-type": "application/json"},
        )
        client_class.return_value.post.return_value = upstream
        llm_proxy.CONFIG["proxy"] = "socks5://global-proxy:1080"
        llm_proxy.CONFIG["channels"][0]["proxy"] = ""

        result = self.client.post(
            "/v1/chat/completions",
            json={"model": "demo-model", "messages": []},
        )

        self.assertEqual(result.status_code, 200)
        self.assertEqual(client_class.call_args.kwargs["proxy"], "socks5://global-proxy:1080")

    @patch("llm_proxy.httpx.get")
    def test_refresh_models_marks_positive_weight_negative_on_failure(self, get):
        response = Mock(status_code=503)
        get.return_value = response
        llm_proxy.CONFIG["channels"][0]["weight"] = 7
        old_models = llm_proxy.CONFIG["channels"][0]["models"]

        result = self.client.post("/admin/api/channels/0/refresh-models")

        self.assertEqual(result.status_code, 502)
        self.assertEqual(llm_proxy.CONFIG["channels"][0]["models"], old_models)
        self.assertEqual(llm_proxy.CONFIG["channels"][0]["weight"], -7)

    @patch("llm_proxy.httpx.get")
    def test_model_refresh_job_returns_immediately_and_completes(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {"data": [{"id": "updated-model"}]}
        get.return_value = response

        started = llm_proxy.time.monotonic()
        create_response = self.client.post(
            "/admin/api/model-refresh-jobs",
            json={"indices": [0]},
        )
        elapsed = llm_proxy.time.monotonic() - started

        self.assertEqual(create_response.status_code, 202)
        self.assertLess(elapsed, 0.5)
        job_id = create_response.get_json()["id"]
        for _ in range(50):
            job = self.client.get(f"/admin/api/model-refresh-jobs/{job_id}").get_json()
            if job["status"] == "completed":
                break
            llm_proxy.time.sleep(0.01)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["success"], 1)
        self.assertEqual(llm_proxy.CONFIG["channels"][0]["models"], ["updated-model"])

    @patch("llm_proxy.httpx.Client")
    def test_upstream_http_error_is_returned_instead_of_generic_bad_gateway(self, client_class):
        upstream = Mock(
            status_code=503,
            content=b'{"error":"upstream unavailable"}',
            text='{"error":"upstream unavailable"}',
            headers={"content-type": "application/json"},
        )
        client_class.return_value.post.return_value = upstream

        response = self.client.post(
            "/v1/chat/completions",
            json={"model": "demo-model", "messages": []},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json(), {"error": "upstream unavailable"})

    def test_circuit_breaker_skips_failed_channel_when_another_is_ready(self):
        candidates = [
            {"name": "quota-empty", "_matched_models": ["model-a"]},
            {"name": "healthy", "_matched_models": ["model-a"]},
        ]
        llm_proxy.mark_upstream_failure("alias", "quota-empty", "model-a", 402)

        selected = llm_proxy.select_upstream_attempts("alias", candidates)

        self.assertEqual(
            [(channel["name"], model) for channel, model in selected],
            [("healthy", "model-a")],
        )

    def test_circuit_breaker_returns_no_attempt_when_all_are_cooling(self):
        candidates = [
            {"name": "quota-empty", "_matched_models": ["model-a"]},
            {"name": "blocked", "_matched_models": ["model-a"]},
        ]
        llm_proxy.mark_upstream_failure("alias", "quota-empty", "model-a", 402)
        llm_proxy.mark_upstream_failure("alias", "blocked", "model-a", 403)

        selected = llm_proxy.select_upstream_attempts("alias", candidates)

        self.assertEqual(selected, [])

    @patch("llm_proxy.httpx.Client")
    def test_all_cooling_upstreams_return_fast_503_instead_of_bad_gateway(self, client_class):
        llm_proxy.mark_upstream_failure("demo-model", "demo", "demo-model", 503)

        response = self.client.post(
            "/v1/chat/completions",
            json={"model": "demo-model", "messages": []},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["error"], "All matching upstreams are cooling down")
        self.assertIn("Retry-After", response.headers)
        client_class.assert_not_called()

    @patch("llm_proxy.time.sleep")
    @patch("llm_proxy.httpx.Client")
    def test_failover_to_unused_channel_does_not_wait_interval(self, client_class, sleep):
        llm_proxy.CONFIG["channels"] = [
            dict(llm_proxy.CONFIG["channels"][0], name="broken", weight=20, interval=10),
            dict(llm_proxy.CONFIG["channels"][0], name="healthy", weight=10, interval=10),
        ]
        failed = Mock(
            status_code=503,
            content=b'{"error":"unavailable"}',
            text='{"error":"unavailable"}',
            headers={"content-type": "application/json"},
        )
        succeeded = Mock(
            status_code=200,
            content=b'{"ok":true}',
            text='{"ok":true}',
            headers={"content-type": "application/json"},
        )
        client_class.return_value.post.side_effect = [failed, succeeded]

        response = self.client.post(
            "/v1/chat/completions",
            json={"model": "demo-model", "messages": []},
        )

        self.assertEqual(response.status_code, 200)
        sleep.assert_not_called()

    @patch("llm_proxy.time.sleep")
    @patch("llm_proxy.httpx.Client")
    def test_first_upstream_attempt_does_not_wait_channel_interval(self, client_class, sleep):
        llm_proxy.CONFIG["channels"][0]["interval"] = 10
        upstream = Mock(
            status_code=200,
            content=b'{"ok":true}',
            text='{"ok":true}',
            headers={"content-type": "application/json"},
        )
        client_class.return_value.post.return_value = upstream

        response = self.client.post(
            "/v1/chat/completions",
            json={"model": "demo-model", "messages": []},
        )

        self.assertEqual(response.status_code, 200)
        sleep.assert_not_called()

    @patch("llm_proxy.time.sleep")
    @patch("llm_proxy.httpx.Client")
    def test_separate_requests_do_not_queue_on_channel_interval(self, client_class, sleep):
        llm_proxy.CONFIG["channels"][0]["interval"] = 10
        upstream = Mock(
            status_code=200,
            content=b'{"ok":true}',
            text='{"ok":true}',
            headers={"content-type": "application/json"},
        )
        client_class.return_value.post.return_value = upstream

        first = self.client.post(
            "/v1/chat/completions",
            json={"model": "demo-model", "messages": []},
        )
        second = self.client.post(
            "/v1/chat/completions",
            json={"model": "demo-model", "messages": []},
        )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        sleep.assert_not_called()

    def test_large_request_body_gets_longer_write_and_read_timeouts(self):
        channel = {"timeout": 66}

        small = llm_proxy.build_upstream_timeout(channel, 10_000)
        large = llm_proxy.build_upstream_timeout(channel, 8 * 1024 * 1024)

        self.assertEqual(small.connect, large.connect)
        self.assertGreater(large.write, small.write)
        self.assertGreater(large.read, small.read)
        self.assertLessEqual(large.write, 600)
        self.assertLessEqual(large.read, 900)

    @patch("llm_proxy.copy.deepcopy")
    @patch("llm_proxy.httpx.Client")
    def test_forward_does_not_deepcopy_large_payload(self, client_class, deepcopy):
        upstream = Mock(
            status_code=200,
            content=b'{"ok":true}',
            text='{"ok":true}',
            headers={"content-type": "application/json"},
        )
        client_class.return_value.post.return_value = upstream

        response = self.client.post(
            "/v1/chat/completions",
            json={
                "model": "demo-model",
                "messages": [{"role": "user", "content": "x" * 1_000_000}],
            },
        )

        self.assertEqual(response.status_code, 200)
        deepcopy.assert_not_called()
        timeout = client_class.call_args.kwargs["timeout"]
        self.assertGreater(timeout.write, llm_proxy.CONFIG["channels"][0]["timeout"])


if __name__ == "__main__":
    unittest.main()
