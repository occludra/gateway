# aisg — Occludra Python SDK

[![PyPI](https://img.shields.io/pypi/v/aisg.svg)](https://pypi.org/project/aisg/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

Python SDK for [Occludra](https://occludra.ai) — PII redaction, prompt injection defense, and smart cost routing for any LLM.

Works with both the **managed cloud** service and **self-hosted** (Docker) deployments.

## Installation

```bash
pip install aisg
```

## Quick Start

```python
from aisg import AISG

client = AISG(api_key="oah_your_project_key")

response = client.chat.create(
    model="oah/llama-4-maverick",
    messages=[{"role": "user", "content": "Explain quantum computing simply."}],
)

print(response.content)
print(response.aisg_metadata.provider_selected)  # e.g. "together"
print(response.aisg_metadata.pii_detected)        # False
print(response.aisg_metadata.cost_usd)            # 0.000042
```

## Configuration

| Parameter | Env Variable | Default | Description |
|-----------|-------------|---------|-------------|
| `api_key` | `AISG_API_KEY` | — | Your API key (required) |
| `base_url` | `AISG_BASE_URL` | `https://api.aisecuritygateway.ai/v1` | API endpoint |
| `timeout` | — | `120` | Request timeout (seconds) |

### Cloud (default)

```python
client = AISG(api_key="oah_abc123")
```

### Self-Hosted

```python
client = AISG(
    api_key="my-gateway-key",
    base_url="http://localhost:8000/v1",
)
```

### Environment Variables

```bash
export AISG_API_KEY="oah_abc123"
export AISG_BASE_URL="https://api.aisecuritygateway.ai/v1"
```

```python
from aisg import AISG
client = AISG()  # picks up from env
```

## Chat Completions

### Basic

```python
response = client.chat.create(
    model="oah/llama-4-maverick",
    messages=[{"role": "user", "content": "Hello!"}],
    max_tokens=512,
    temperature=0.7,
)

print(response.content)
print(response.usage.total_tokens)
```

### Streaming

```python
for chunk in client.chat.create(
    model="oah/llama-4-maverick",
    messages=[{"role": "user", "content": "Write a poem."}],
    stream=True,
):
    delta = chunk.get("choices", [{}])[0].get("delta", {})
    print(delta.get("content", ""), end="", flush=True)
```

### With Routing Headers

```python
response = client.chat.create(
    model="oah/llama-4-maverick",
    messages=[{"role": "user", "content": "Hello!"}],
    extra_headers={
        "x-provider": "together",     # pin to a specific provider
        "x-feature": "chatbot-v2",    # analytics tag
        "x-env": "production",        # environment tag
    },
)
```

### OpenAI SDK Compatibility

The Occludra API is fully OpenAI-compatible. You can also use the OpenAI SDK directly:

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://api.aisecuritygateway.ai/v1",
    api_key="oah_abc123",
)

response = client.chat.completions.create(
    model="oah/llama-4-maverick",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

The Occludra SDK adds typed metadata, structured error handling, and model discovery on top.

## Model Discovery

```python
# List all models
models = client.models.list()
for m in models:
    print(f"{m.id}: {m.family}, vision={m.supports_vision}")
    print(f"  ${m.pricing.input_per_1m_tokens}/1M input tokens")

# Filter by family
llama_models = client.models.list(family="llama")

# Filter by capability
vision_models = client.models.list(capability="vision")

# Filter by provider
together_models = client.models.list(provider="together")
```

## Security Metadata

Every response includes `aisg_metadata` with security and routing information:

```python
response = client.chat.create(
    model="oah/llama-4-maverick",
    messages=[{"role": "user", "content": "Email john@example.com about the project."}],
)

meta = response.aisg_metadata
print(meta.pii_detected)          # True
print(meta.dlp_action)            # "redact"
print(meta.entity_types_detected) # ["EMAIL_ADDRESS"]
print(meta.dlp_latency_ms)        # 28.0
print(meta.provider_selected)     # "together"
print(meta.routing_mode)          # "smart_route"
print(meta.cost_usd)              # 0.000042
```

## Error Handling

```python
from aisg import AISG, DLPBlockError, BudgetExhaustedError, RateLimitError, ModelNotFoundError

client = AISG(api_key="oah_abc123")

try:
    response = client.chat.create(
        model="oah/llama-4-maverick",
        messages=[{"role": "user", "content": "My SSN is 123-45-6789"}],
    )
except DLPBlockError as e:
    print(f"Blocked: {e.violations}")
    print(f"Request ID: {e.request_id}")

except BudgetExhaustedError:
    print("Project budget exhausted — upgrade or add credits")

except RateLimitError:
    print("Rate limited — back off and retry")

except ModelNotFoundError as e:
    print(f"Model unavailable. Try: {e.suggested_model}")
```

## Async Client

```python
import asyncio
from aisg import AsyncAISG

async def main():
    async with AsyncAISG(api_key="oah_abc123") as client:
        response = await client.chat.create(
            model="oah/llama-4-maverick",
            messages=[{"role": "user", "content": "Hello!"}],
        )
        print(response.content)

        models = await client.models.list(family="llama")
        for m in models:
            print(m.id)

asyncio.run(main())
```

## Response Types

All responses are typed dataclasses:

| Type | Description |
|------|-------------|
| `ChatCompletion` | Full chat response with `.content`, `.usage`, `.aisg_metadata` |
| `AISGMetadata` | Security metadata: PII detection, routing, costs |
| `ModelInfo` | Model entry with capabilities, pricing, providers |
| `DLPViolation` | Detected PII entity with type, position, confidence |

## Links

- [Documentation](https://occludra.ai/docs)
- [OpenAPI Spec](https://occludra.ai/openapi.yaml)
- [GitHub](https://github.com/occludra/gateway)
- [Status](https://status.occludra.ai)

## License

Apache 2.0 — see [LICENSE](LICENSE).
