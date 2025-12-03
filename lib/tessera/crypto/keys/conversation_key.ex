defmodule Tessera.Crypto.Keys.ConversationKey do
  @moduledoc """
  Conversation key in the hierarchical key derivation system.

  Conversation keys are derived from root keys and provide compartmentalization
  for different resource groups or conversations. Each conversation has its own
  isolated key branch.

  ## Key Hierarchy

  ```
  RootKey
      └── ConversationKey (this level)
              └── EpochKey
                      └── MessageKey
  ```

  ## Use Cases

  - Separate encryption domains for different users
  - Isolate data categories (medical, financial, social)
  - Multi-tenant key separation
  """

  alias Tessera.Crypto.Keys.RootKey

  @enforce_keys [:material, :conversation_id, :created_at]
  defstruct [:material, :conversation_id, :created_at, :key_id, :parent_fingerprint]

  @type t :: %__MODULE__{
          material: binary(),
          conversation_id: String.t(),
          created_at: DateTime.t(),
          key_id: String.t() | nil,
          parent_fingerprint: String.t() | nil
        }

  @doc """
  Creates a new conversation key from derived material.
  """
  @spec new(binary(), String.t(), RootKey.t()) :: t()
  def new(material, conversation_id, %RootKey{} = parent)
      when is_binary(material) and byte_size(material) == 32 and is_binary(conversation_id) do
    %__MODULE__{
      material: material,
      conversation_id: conversation_id,
      created_at: DateTime.utc_now(),
      key_id: generate_key_id(material),
      parent_fingerprint: RootKey.fingerprint(parent)
    }
  end

  @doc """
  Returns a truncated key ID for identification without exposing material.
  """
  @spec fingerprint(t()) :: String.t()
  def fingerprint(%__MODULE__{key_id: key_id}) do
    String.slice(key_id, 0, 16)
  end

  defp generate_key_id(material) do
    :crypto.hash(:sha256, material)
    |> Base.encode16(case: :lower)
    |> String.slice(0, 32)
  end

  defimpl Inspect do
    def inspect(
          %Tessera.Crypto.Keys.ConversationKey{
            key_id: key_id,
            conversation_id: conv_id,
            created_at: created_at
          },
          _opts
        ) do
      fingerprint = String.slice(key_id || "", 0, 8)
      "#ConversationKey<#{fingerprint}... conv: #{conv_id}, created_at: #{created_at}>"
    end
  end
end
