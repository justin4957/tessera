defmodule Tessera.Crypto.Keys.MessageKey do
  @moduledoc """
  Message key in the hierarchical key derivation system.

  Message keys are the leaf keys used for actual encryption of resources.
  Each resource should have its own unique message key, derived from its
  parent epoch key.

  ## Key Hierarchy

  ```
  RootKey
      └── ConversationKey
              └── EpochKey
                      └── MessageKey (this level - leaf)
  ```

  ## Usage

  Message keys are used directly for:
  - Encrypting resource content (AES-256-GCM recommended)
  - Deriving additional sub-keys if needed (HKDF)
  - MAC computation for integrity

  ## Resource Binding

  The message key is bound to a specific resource ID, ensuring:
  - Each resource has a unique encryption key
  - Resource ID changes result in different keys
  - Key reuse across resources is prevented
  """

  alias Tessera.Crypto.Keys.EpochKey

  @enforce_keys [:material, :resource_id, :created_at, :parent]
  defstruct [:material, :resource_id, :created_at, :key_id, :parent]

  @type t :: %__MODULE__{
          material: binary(),
          resource_id: String.t(),
          created_at: DateTime.t(),
          key_id: String.t() | nil,
          parent: EpochKey.t()
        }

  @doc """
  Creates a new message key from derived material.
  """
  @spec new(binary(), String.t(), EpochKey.t()) :: t()
  def new(material, resource_id, %EpochKey{} = parent)
      when is_binary(material) and byte_size(material) == 32 and is_binary(resource_id) do
    %__MODULE__{
      material: material,
      resource_id: resource_id,
      created_at: DateTime.utc_now(),
      key_id: generate_key_id(material),
      parent: parent
    }
  end

  @doc """
  Returns a truncated key ID for identification without exposing material.
  """
  @spec fingerprint(t()) :: String.t()
  def fingerprint(%__MODULE__{key_id: key_id}) do
    String.slice(key_id, 0, 16)
  end

  @doc """
  Returns the epoch number this message key belongs to.
  """
  @spec epoch_number(t()) :: non_neg_integer()
  def epoch_number(%__MODULE__{parent: parent}) do
    parent.epoch_number
  end

  @doc """
  Returns the conversation ID this message key belongs to.
  """
  @spec conversation_id(t()) :: String.t()
  def conversation_id(%__MODULE__{parent: parent}) do
    EpochKey.conversation_id(parent)
  end

  @doc """
  Returns the raw key material for use in encryption.

  **Security Warning**: Handle the returned bytes carefully.
  Do not log or expose this value.
  """
  @spec to_bytes(t()) :: binary()
  def to_bytes(%__MODULE__{material: material}) do
    material
  end

  defp generate_key_id(material) do
    :crypto.hash(:sha256, material)
    |> Base.encode16(case: :lower)
    |> String.slice(0, 32)
  end

  defimpl Inspect do
    def inspect(
          %Tessera.Crypto.Keys.MessageKey{
            key_id: key_id,
            resource_id: resource_id,
            parent: parent,
            created_at: created_at
          },
          _opts
        ) do
      fingerprint = String.slice(key_id || "", 0, 8)
      epoch = parent.epoch_number

      "#MessageKey<#{fingerprint}... resource: #{resource_id}, epoch: #{epoch}, created_at: #{created_at}>"
    end
  end
end
