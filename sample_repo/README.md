# FleetLine portal

Customer and driver portal of FleetLine Logistics. Python backend, static frontend, Terraform for the AWS account.

## Configuration

Copy `.env.example` to `.env` and fill in the values. Third-party keys go in `config/integrations.yaml`:

```yaml
api_key = "<your-key>"
```

Run `make dev` for a local server and `make test` for the suite.
