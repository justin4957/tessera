import Config

# Tessera configuration
# Configure the default store adapter
config :tessera, :default_store, Tessera.Stores.Memory.Adapter

# Import environment specific config
import_config "#{config_env()}.exs"
