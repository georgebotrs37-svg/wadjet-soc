import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx

import main


class SiemIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_patch = patch.object(
            main,
            "DATABASE_PATH",
            Path(self.temp_directory.name) / "test.db",
        )
        self.database_patch.start()
        self.environment_patch = patch.dict(
            os.environ,
            {
                "WAZUH_INDEXER_URL": "https://wazuh.test:9200",
                "WAZUH_INDEXER_USERNAME": "read-only",
                "WAZUH_INDEXER_PASSWORD": "test-password",
                "WAZUH_INDEXER_INDEX_PATTERN": "wazuh-alerts-4.x-*",
                "SPLUNK_URL": "https://splunk.test:8089",
                "SPLUNK_TOKEN": "test-token",
                "SPLUNK_SEARCH_QUERY": "search index=security sourcetype=alerts | head 100",
            },
        )
        self.environment_patch.start()
        self.splunk_status = 200
        self.received_requests: list[httpx.Request] = []
        self.transport = httpx.MockTransport(self._respond)
        self.transport_patch = patch.object(main, "SIEM_HTTP_TRANSPORT", self.transport)
        self.transport_patch.start()
        main.initialize_database()
        salt = b"test-admin-salt"
        with main.connect_database() as connection:
            connection.execute(
                "INSERT INTO admins (id, email, password_salt, password_hash, created_at) "
                "VALUES (1, ?, ?, ?, ?)",
                (
                    "analyst@gmail.com",
                    salt,
                    main.hash_password("correct-test-password", salt),
                    main.utc_now(),
                ),
            )
        self.lifespan = main.app.router.lifespan_context(main.app)
        await self.lifespan.__aenter__()
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app),
            base_url="http://soc.test",
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        await self.lifespan.__aexit__(None, None, None)
        self.transport_patch.stop()
        self.environment_patch.stop()
        self.database_patch.stop()
        self.temp_directory.cleanup()

    async def _respond(self, request: httpx.Request) -> httpx.Response:
        self.received_requests.append(request)
        if request.url.host == "wazuh.test":
            self.assertEqual(request.method, "POST")
            self.assertIn("/wazuh-alerts-4.x-*/_search", request.url.path)
            self.assertEqual(request.headers.get("authorization"), "Basic cmVhZC1vbmx5OnRlc3QtcGFzc3dvcmQ=")
            self.assertEqual(json.loads(request.content)["size"], 60)
            return httpx.Response(
                200,
                json={
                    "hits": {
                        "hits": [
                            {
                                "_id": "wazuh-123",
                                "_source": {
                                    "@timestamp": "2026-10-09T20:00:00Z",
                                    "rule": {
                                        "id": "5710",
                                        "description": "Repeated SSH login failures",
                                        "level": 12,
                                        "mitre": {"id": ["T1110.001"]},
                                    },
                                    "agent": {"name": "edge-01"},
                                    "data": {"srcip": "198.51.100.10"},
                                },
                            }
                        ]
                    }
                },
            )
        self.assertEqual(request.url.host, "splunk.test")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.url.path, "/services/search/jobs/export")
        self.assertEqual(request.headers.get("authorization"), "Bearer test-token")
        if self.splunk_status != 200:
            return httpx.Response(self.splunk_status, json={"messages": [{"text": "unauthorized"}]})
        return httpx.Response(
            200,
            text=(
                json.dumps(
                    {
                        "preview": False,
                        "result": {
                            "_time": "2026-10-09T19:59:00Z",
                            "_raw": json.dumps(
                                {
                                    "description": "Suspicious PowerShell",
                                    "rule": {"level": 9, "mitre": {"id": ["T1059.001"]}},
                                }
                            ),
                            "host": "endpoint-01",
                            "src_ip": "203.0.113.9",
                        },
                    }
                )
                + "\n"
            ),
        )

    async def _login(self) -> None:
        response = await self.client.post(
            "/api/auth/login",
            json={"email": "analyst@gmail.com", "password": "correct-test-password"},
        )
        self.assertEqual(response.status_code, 200)

    async def test_siem_endpoints_require_an_admin_session(self) -> None:
        response = await self.client.get("/api/siem/alerts")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.received_requests, [])

    async def test_navigation_preferences_require_login_and_default_per_admin(self) -> None:
        response = await self.client.get("/api/settings/navigation")
        self.assertEqual(response.status_code, 401)

        await self._login()
        response = await self.client.get("/api/settings/navigation")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"order": list(main.NAVIGATION_ORDER), "hidden": []},
        )

    async def test_navigation_preferences_are_validated_and_persisted(self) -> None:
        await self._login()
        preferences = {
            "order": list(reversed(main.NAVIGATION_ORDER)),
            "hidden": ["analytics", "timeline"],
        }
        response = await self.client.put("/api/settings/navigation", json=preferences)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), preferences)
        persisted = await self.client.get("/api/settings/navigation")
        self.assertEqual(persisted.json(), preferences)

        required_hidden = await self.client.put(
            "/api/settings/navigation",
            json={"order": list(main.NAVIGATION_ORDER), "hidden": ["settings"]},
        )
        self.assertEqual(required_hidden.status_code, 422)
        incomplete_order = await self.client.put(
            "/api/settings/navigation",
            json={"order": list(main.NAVIGATION_ORDER[:-1]), "hidden": []},
        )
        self.assertEqual(incomplete_order.status_code, 422)

    async def test_both_siem_feeds_are_normalized_for_the_dashboard(self) -> None:
        await self._login()
        response = await self.client.get("/api/siem/alerts?limit=60")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual([provider["status"] for provider in payload["providers"]], ["connected", "connected"])
        self.assertEqual(payload["count"], 2)
        wazuh_alert = next(alert for alert in payload["alerts"] if alert["provider"] == "Wazuh")
        self.assertEqual(wazuh_alert["severity"], "Critical")
        self.assertEqual(wazuh_alert["technique"], "T1110.001")
        self.assertEqual(wazuh_alert["source_ip"], "198.51.100.10")
        splunk_alert = next(alert for alert in payload["alerts"] if alert["provider"] == "Splunk")
        self.assertEqual(splunk_alert["severity"], "High")
        self.assertEqual(splunk_alert["technique"], "T1059.001")
        self.assertEqual(splunk_alert["agent"], "endpoint-01")

    async def test_splunk_error_does_not_hide_wazuh_alerts(self) -> None:
        await self._login()
        self.splunk_status = 401
        response = await self.client.get("/api/siem/alerts")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["providers"][0]["status"], "connected")
        self.assertEqual(payload["providers"][1]["status"], "error")
        self.assertEqual(payload["providers"][1]["error"], "Splunk returned HTTP 401.")
        self.assertEqual([alert["provider"] for alert in payload["alerts"]], ["Wazuh"])

    async def test_unconfigured_feed_is_explicit_and_does_not_attempt_a_request(self) -> None:
        await self._login()
        with patch.dict(os.environ, {"SPLUNK_TOKEN": "", "WAZUH_INDEXER_PASSWORD": ""}):
            response = await self.client.get("/api/siem/alerts")

        self.assertEqual(response.status_code, 200)
        self.assertEqual([provider["status"] for provider in response.json()["providers"]], ["not_configured", "not_configured"])
        self.assertEqual(self.received_requests, [])

    async def test_splunk_write_capable_search_is_rejected(self) -> None:
        await self._login()
        with patch.dict(
            os.environ,
            {"SPLUNK_SEARCH_QUERY": "search index=security | outputlookup stolen.csv"},
        ):
            response = await self.client.get("/api/siem/alerts")

        payload = response.json()
        self.assertEqual(payload["providers"][1]["status"], "error")
        self.assertEqual(payload["providers"][1]["error"], "SPLUNK_SEARCH_QUERY contains a write-capable command.")
        self.assertFalse(any(request.url.host == "splunk.test" for request in self.received_requests))


if __name__ == "__main__":
    unittest.main()
