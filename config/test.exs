import Config

# Test-specific configuration

# Use mock HTTP client in tests
config :tessera, :http_client, Tessera.MockHTTPClient
