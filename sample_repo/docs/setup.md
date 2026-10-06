# Developer setup

1. Create a virtualenv and install `requirements.txt`.
2. Copy `.env.example` to `.env`.
3. Request an integration token from the CRM administrator and set it in `config/integrations.yaml`, for example:

```python
token = "example-token-value"
```

4. Run `make dev`.
