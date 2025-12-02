ExUnit.start()

# Define mock for HTTP client
Mox.defmock(Tessera.MockHTTPClient, for: Tessera.HTTPClientBehaviour)
