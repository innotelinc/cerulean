import os
import tempfile
import unittest
from pathlib import Path

from cerulean_integration.config import load_config


class LoadConfigTest(unittest.TestCase):
    def test_defaults(self):
        cfg = load_config(overrides={"password": "x", "hosts_file": "h.conf"})
        self.assertEqual(cfg.api_url, "http://localhost:3003")
        self.assertEqual(cfg.base_domain, "innotel.us")
        self.assertEqual(cfg.password, "x")
        self.assertEqual(cfg.hosts_file, "h.conf")

    def test_dotenv_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text(
                "CERULEAN_API_URL=http://cerulean.example:9999\n"
                "CERULEAN_BASE_DOMAIN=example.com\n"
                "CERULEAN_ZONE=example.com\n"
                "NPM_FORWARD_HOST=10.0.0.5\n"
            )
            cfg = load_config(dotenv_path=Path(tmp, ".env"), overrides={"password": "p"})
            self.assertEqual(cfg.api_url, "http://cerulean.example:9999")
            self.assertEqual(cfg.base_domain, "example.com")
            self.assertEqual(cfg.zone, "example.com")
            self.assertEqual(cfg.forward_host, "10.0.0.5")

    def test_environment_wins_over_dotenv(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".env").write_text("CERULEAN_BASE_DOMAIN=dotenv-base\n")
            old = os.environ.get("CERULEAN_BASE_DOMAIN")
            os.environ["CERULEAN_BASE_DOMAIN"] = "env-base"
            try:
                cfg = load_config(
                    dotenv_path=Path(tmp, ".env"), overrides={"password": "p"}
                )
                self.assertEqual(cfg.base_domain, "env-base")
            finally:
                if old is None:
                    os.environ.pop("CERULEAN_BASE_DOMAIN", None)
                else:
                    os.environ["CERULEAN_BASE_DOMAIN"] = old

    def test_overrides_win_over_everything(self):
        cfg = load_config(
            overrides={"password": "p", "base_domain": "cli-zone", "dry_run": True}
        )
        self.assertEqual(cfg.base_domain, "cli-zone")
        self.assertTrue(cfg.dry_run)


if __name__ == "__main__":
    unittest.main()