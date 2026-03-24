import os

import openai
import pytest

from cai.sdk.agents import set_default_openai_api, set_default_openai_client, set_default_openai_key
from cai.sdk.agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from cai.sdk.agents.models import openai_provider as openai_provider_module
from cai.sdk.agents.models.openai_provider import OpenAIProvider
from cai.sdk.agents.models.openai_responses import OpenAIResponsesModel


import os
cai_model = os.getenv('CAI_MODEL', "qwen2.5:14b")

def test_cc_no_default_key_errors(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(openai.OpenAIError):
        OpenAIProvider(use_responses=False).get_model(cai_model)


def test_cc_set_default_openai_key():
    set_default_openai_key("test_key")
    chat_model = OpenAIProvider(use_responses=False).get_model(cai_model)
    assert chat_model._client.api_key == "test_key"  # type: ignore


def test_cc_set_default_openai_client():
    client = openai.AsyncOpenAI(api_key="test_key")
    set_default_openai_client(client)
    chat_model = OpenAIProvider(use_responses=False).get_model(cai_model)
    assert chat_model._client.api_key == "test_key"  # type: ignore


def test_resp_no_default_key_errors(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert os.getenv("OPENAI_API_KEY") is None
    with pytest.raises(openai.OpenAIError):
        OpenAIProvider(use_responses=True).get_model(cai_model)


def test_resp_set_default_openai_key():
    set_default_openai_key("test_key")
    resp_model = OpenAIProvider(use_responses=True).get_model(cai_model)
    assert resp_model._client.api_key == "test_key"  # type: ignore


def test_resp_set_default_openai_client():
    client = openai.AsyncOpenAI(api_key="test_key")
    set_default_openai_client(client)
    resp_model = OpenAIProvider(use_responses=True).get_model(cai_model)
    assert resp_model._client.api_key == "test_key"  # type: ignore


def test_set_default_openai_api():
    assert isinstance(OpenAIProvider().get_model(cai_model), OpenAIResponsesModel), (
        "Default should be responses"
    )

    set_default_openai_api("chat_completions")
    assert isinstance(OpenAIProvider().get_model(cai_model), OpenAIChatCompletionsModel), (
        "Should be chat completions model"
    )

    set_default_openai_api("responses")
    assert isinstance(OpenAIProvider().get_model(cai_model), OpenAIResponsesModel), (
        "Should be responses model"
    )


def test_cai_openai_base_url_applies_when_base_url_not_passed(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test_key")
    monkeypatch.setenv(
        "CAI_OPENAI_BASE_URL",
        "https://e0f1-196-157-78-53.ngrok-free.app/v1/chat/completions",
    )
    monkeypatch.setattr(openai_provider_module._openai_shared, "get_default_openai_client", lambda: None)

    model = OpenAIProvider(use_responses=False).get_model(cai_model)
    assert str(model._client.base_url) == "https://e0f1-196-157-78-53.ngrok-free.app/v1/"  # type: ignore


def test_explicit_base_url_takes_precedence_over_cai_openai_base_url(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test_key")
    monkeypatch.setenv("CAI_OPENAI_BASE_URL", "https://example.com/v1")
    monkeypatch.setattr(openai_provider_module._openai_shared, "get_default_openai_client", lambda: None)

    model = OpenAIProvider(
        base_url="https://override.example/v1",
        use_responses=False,
    ).get_model(cai_model)
    assert str(model._client.base_url) == "https://override.example/v1/"  # type: ignore
