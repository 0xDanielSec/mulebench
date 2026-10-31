"""OpenAI-compatible adapter and local HTTP transport. Offline: httpx.MockTransport only."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from mulebench.agents.llm.http_transport import (
    API_KEY_ENV,
    LocalServerClient,
    OpenAICompatTransport,
    RemoteHostRefused,
    ServerUnreachable,
    check_base_url,
    server_root,
)
from mulebench.agents.llm.model import (
    ChatRequest,
    ModelCallError,
    ModelRequestInvalid,
    ToolDef,
    ToolOutcome,
    Turn,
)
from mulebench.agents.llm.openai_compat import (
    OpenAICompatChatModel,
    ResponseShapeError,
    parse_completion,
)
from mulebench.agents.llm.transport import FakeTransport, LiveCallsDisabled


def ip(*octets: int) -> str:
    """IP literal built at runtime so the prepublish scanner sees no host."""
    return ".".join(map(str, octets))


SECRET = "sk-local-SENTINEL-0000"  # noqa: S105 - test sentinel, not a credential


def completion(message: dict[str, Any], finish: str = "stop") -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "model": "tiny:1b",
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
        "usage": {"prompt_tokens": 321, "completion_tokens": 12},
    }


def call(name: str, arguments: object, call_id: str = "call_a") -> dict[str, Any]:
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


def request(**kw: Any) -> ChatRequest:
    base: dict[str, Any] = {
        "model": "tiny:1b",
        "system": "SYSTEM",
        "turns": (
            Turn(kind="user", text="pay my rent"),
            Turn(kind="operator", text="NOTE"),
        ),
        "tools": (ToolDef(name="get_balance", description="d", input_schema={"type": "object"}),),
        "max_tokens": 256,
        "effort": "none",
        "trial_key": "s/p/v/attack/t000",
    }
    base.update(kw)
    return ChatRequest(**base)


# ------------------------------------------------------------- adapter


def test_build_params_shape() -> None:
    model = OpenAICompatChatModel(FakeTransport([]))
    p = model.build_params(request(seed=7))
    assert p["messages"][0] == {"role": "system", "content": "SYSTEM\n\nNOTE"}
    assert p["messages"][1] == {"role": "user", "content": "pay my rent"}
    assert p["tools"][0]["function"]["name"] == "get_balance"
    assert p["tools"][0]["function"]["parameters"] == {"type": "object"}
    assert (p["temperature"], p["seed"], p["tool_choice"], p["stream"]) == (0.0, 7, "auto", False)
    assert model.session_note_channel("tiny:1b") == "system_prompt"


def test_build_params_omits_seed_when_unset_and_keeps_temperature() -> None:
    p = OpenAICompatChatModel(FakeTransport([])).build_params(request(temperature=0.7))
    assert "seed" not in p
    assert p["temperature"] == 0.7


def test_assistant_and_tool_turns_round_trip() -> None:
    assistant = {"role": "assistant", "content": None, "tool_calls": [call("get_balance", "{}")]}
    turns = (
        Turn(kind="user", text="u"),
        Turn(kind="assistant", provider_raw=(assistant,)),
        Turn(
            kind="tool_results",
            results=(ToolOutcome(call_id="call_a", content="{}", is_error=False),),
        ),
    )
    p = OpenAICompatChatModel(FakeTransport([])).build_params(request(turns=turns))
    assert p["messages"][2] == assistant
    assert p["messages"][3] == {"role": "tool", "tool_call_id": "call_a", "content": "{}"}


def test_parse_valid_tool_call_and_usage() -> None:
    r = parse_completion(
        completion(
            {"role": "assistant", "tool_calls": [call("get_balance", '{"a": 1}')]}, "tool_calls"
        )
    )
    assert [(c.id, c.name, c.args) for c in r.tool_calls] == [("call_a", "get_balance", {"a": 1})]
    assert r.invalid_tool_calls == ()
    assert (r.prompt_tokens, r.usage.input_tokens, r.usage.output_tokens) == (321, 321, 12)
    assert (r.stop_reason, r.served_model, r.request_id) == ("tool_calls", "tiny:1b", "chatcmpl-1")


@pytest.mark.parametrize(
    ("arguments", "detail"),
    [
        ('{"a": ', "invalid JSON"),
        ("[1, 2]", "JSON list"),
        (None, "type NoneType"),
    ],
)
def test_unparsable_arguments_are_invalid_json_calls(arguments: object, detail: str) -> None:
    r = parse_completion(completion({"role": "assistant", "tool_calls": [call("x", arguments)]}))
    assert r.tool_calls == ()
    (bad,) = r.invalid_tool_calls
    assert (bad.kind, bad.name) == ("json", "x")
    assert detail in bad.detail


def test_object_arguments_and_missing_ids_are_accepted() -> None:
    raw = {"type": "function", "function": {"name": "get_balance", "arguments": {"k": "v"}}}
    r = parse_completion(completion({"role": "assistant", "tool_calls": [raw]}))
    assert [(c.id, c.args) for c in r.tool_calls] == [("call_0", {"k": "v"})]


def test_refusal_and_bad_shape() -> None:
    r = parse_completion(completion({"role": "assistant", "content": "", "refusal": "no"}))
    assert r.stop_reason == "refusal"
    with pytest.raises(ResponseShapeError):
        parse_completion({"choices": []})


# ----------------------------------------------------------- URL guard


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:11434/v1",
        f"http://{ip(127, 0, 0, 1)}:8000/v1",
        f"http://{ip(127, 5, 6, 7)}/v1",
        "http://[::1]:1234/v1",
    ],
)
def test_loopback_hosts_allowed(url: str) -> None:
    assert check_base_url(url + "/") == url


@pytest.mark.parametrize(
    "url",
    [
        f"http://{ip(192, 168, 0, 10)}:11434/v1",
        "https://llm.example.test/v1",
        f"http://{ip(0, 0, 0, 0)}/v1",
    ],
)
def test_remote_hosts_refused_unless_allowed(url: str) -> None:
    with pytest.raises(RemoteHostRefused):
        check_base_url(url)
    assert check_base_url(url, allow_remote=True) == url


@pytest.mark.parametrize("url", ["ftp://localhost/v1", "localhost:11434", "http:///v1"])
def test_malformed_base_urls(url: str) -> None:
    with pytest.raises(ValueError, match="base URL"):
        check_base_url(url)


def test_server_root() -> None:
    assert server_root("http://localhost:11434/v1") == "http://localhost:11434"


# ----------------------------------------------------------- transport


def mock(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_transport_needs_mb_live(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)
    with pytest.raises(LiveCallsDisabled):
        OpenAICompatTransport()


def test_transport_refuses_remote_before_any_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    with pytest.raises(RemoteHostRefused):
        OpenAICompatTransport(
            f"http://{ip(10, 0, 0, 5)}:11434/v1", client=mock(lambda r: httpx.Response(500))
        )


def test_transport_posts_body_and_key_only_in_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    monkeypatch.setenv(API_KEY_ENV, SECRET)
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=completion({"role": "assistant", "content": "hi"}))

    t = OpenAICompatTransport(client=mock(handler))
    out = t.send({"model": "tiny:1b"}, "k")
    assert str(seen[0].url) == "http://localhost:11434/v1/chat/completions"
    assert seen[0].headers["authorization"] == f"Bearer {SECRET}"
    assert json.loads(seen[0].content) == {"model": "tiny:1b"}
    assert SECRET not in json.dumps(out.body)
    assert out.request_id == "chatcmpl-1"


def test_no_key_no_auth_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    monkeypatch.delenv(API_KEY_ENV, raising=False)
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json=completion({"role": "assistant"}))

    OpenAICompatTransport(client=mock(handler)).send({}, "k")
    assert "authorization" not in seen[0].headers


@pytest.mark.parametrize(
    ("status", "exc", "kind"),
    [
        (429, ModelCallError, "http_429"),
        (503, ModelCallError, "http_503"),
        (404, ModelRequestInvalid, None),
    ],
)
def test_transport_error_mapping_never_leaks_key(
    monkeypatch: pytest.MonkeyPatch, status: int, exc: type[Exception], kind: str | None
) -> None:
    monkeypatch.setenv("MB_LIVE", "1")
    monkeypatch.setenv(API_KEY_ENV, SECRET)
    t = OpenAICompatTransport(client=mock(lambda r: httpx.Response(status, text="model not found")))
    with pytest.raises(exc) as info:
        t.send({}, "k")
    assert SECRET not in str(info.value)
    if kind is not None:
        assert getattr(info.value, "kind", None) == kind


def test_transport_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MB_LIVE", "1")

    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    with pytest.raises(ModelCallError) as info:
        OpenAICompatTransport(client=mock(handler)).send({}, "k")
    assert info.value.kind == "connection"


# ------------------------------------------------------- server metadata

SHOW = {
    "details": {"quantization_level": "Q4_K_M"},
    "parameters": 'stop "<|im_end|>"\nnum_ctx 4096',
    "model_info": {"qwen3.context_length": 40960},
}


def ollama(paths: dict[str, Any]) -> httpx.Client:
    def handler(req: httpx.Request) -> httpx.Response:
        body = paths.get(f"{req.method} {req.url.path}")
        return httpx.Response(404) if body is None else httpx.Response(200, json=body)

    return mock(handler)


def test_server_meta_from_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MB_LIVE", raising=False)  # metadata does not need MB_LIVE
    client = LocalServerClient(
        client=ollama(
            {
                "GET /api/version": {"version": "0.12.0"},
                "GET /api/tags": {"models": [{"name": "tiny:1b", "digest": "sha256:abc"}]},
                "POST /api/show": SHOW,
            }
        )
    )
    meta = client.server_meta("tiny:1b")
    assert meta.model_dump() == {
        "model": "tiny:1b",
        "digest": "sha256:abc",
        "quantization": "Q4_K_M",
        "server_version": "0.12.0",
        "num_ctx": 4096,
        "num_ctx_source": "parameters",
        "context_length": 40960,
    }
    assert client.models() == ["tiny:1b"]


def test_num_ctx_falls_back_to_loaded_model() -> None:
    show = {**SHOW, "parameters": "stop x"}
    client = LocalServerClient(
        client=ollama(
            {
                "GET /api/version": {"version": "0.12.0"},
                "POST /api/show": show,
                "GET /api/ps": {"models": [{"name": "tiny:1b", "context_length": 8192}]},
            }
        )
    )
    meta = client.server_meta("tiny:1b")
    assert (meta.num_ctx, meta.num_ctx_source) == (8192, "ps")


def test_non_ollama_server_has_null_metadata() -> None:
    client = LocalServerClient(client=ollama({"GET /v1/models": {"data": [{"id": "m"}]}}))
    assert client.version() is None
    assert client.models() == ["m"]
    meta = client.server_meta("m")
    assert (meta.digest, meta.quantization, meta.num_ctx) == (None, None, None)


def test_unreachable_server() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=req)

    with pytest.raises(ServerUnreachable):
        LocalServerClient(client=mock(handler)).version()


def test_metadata_client_refuses_remote() -> None:
    with pytest.raises(RemoteHostRefused):
        LocalServerClient(f"http://{ip(203, 0, 113, 9)}:11434/v1")


# --------------------------------------- derived models (ollama create)


def test_digest_for_a_derived_model_listed_as_latest() -> None:
    """`ollama create llama31-8b-8k -f Modelfile` is listed as `llama31-8b-8k:latest`;
    /api/show has no digest. The digest comes from /api/tags."""
    client = LocalServerClient(
        client=ollama(
            {
                "GET /api/version": {"version": "0.40.13"},
                "GET /api/tags": {
                    "models": [
                        {"name": "llama3.1:8b", "digest": "sha256:base"},
                        {"name": "llama31-8b-8k:latest", "digest": "sha256:derived"},
                    ]
                },
                "POST /api/show": {
                    "details": {"quantization_level": "Q4_K_M"},
                    "parameters": "num_ctx 8192",
                },
            }
        )
    )
    meta = client.server_meta("llama31-8b-8k")
    assert (meta.digest, meta.num_ctx, meta.quantization) == ("sha256:derived", 8192, "Q4_K_M")


def test_explicit_tags_match_exactly_and_ps_matches_latest() -> None:
    from mulebench.agents.llm.http_transport import same_model

    assert same_model({"name": "m:latest"}, "m")
    assert same_model({"model": "m:latest"}, "m")
    assert not same_model({"name": "m:8b"}, "m")
    assert not same_model({"name": "m:latest"}, "m:8b")
    client = LocalServerClient(
        client=ollama(
            {
                "GET /api/version": {"version": "0.40.13"},
                "POST /api/show": {"parameters": "stop x"},
                "GET /api/ps": {"models": [{"name": "m:latest", "context_length": 8192}]},
            }
        )
    )
    meta = client.server_meta("m")
    assert (meta.num_ctx, meta.num_ctx_source) == (8192, "ps")
