defmodule Tessera.Crypto.KeyDerivation do
  @moduledoc """
  Hierarchical key derivation for temporal data sovereignty.

  Implements HKDF-based (RFC 5869) key derivation with a structured hierarchy:

  ```
  UserRoot Key
      │
      ├── ConversationRoot Key (per conversation/resource group)
      │       │
      │       ├── EpochKey (time-bounded)
      │       │       │
      │       │       └── MessageKey (per resource)
      │       │
      │       └── EpochKey (next epoch)
      │
      └── ConversationRoot Key (another conversation)
  ```

  ## Security Properties

  - **Key Isolation**: Compromise of one branch doesn't affect others
  - **Forward Secrecy**: Past keys not derivable from current state
  - **Deterministic**: Same inputs always produce same outputs
  - **Domain Separation**: Each key type uses unique context

  ## Usage

      # Generate a new root key
      {:ok, root_key} = KeyDerivation.generate_root_key()

      # Derive conversation key
      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "conv-123")

      # Derive epoch key
      {:ok, epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 1)

      # Derive message key
      {:ok, msg_key} = KeyDerivation.derive_message_key(epoch_key, "resource-id")

      # Or use path notation
      {:ok, key} = KeyDerivation.derive_path(root_key, "m/conv/abc/epoch/5/msg/doc-1")
  """

  alias Tessera.Crypto.Keys.{RootKey, ConversationKey, EpochKey, MessageKey}

  @key_length 32
  @hash_algorithm :sha256

  # Domain separation constants for HKDF info parameter
  @domain_root "tessera.v1.root"
  @domain_conversation "tessera.v1.conversation"
  @domain_epoch "tessera.v1.epoch"
  @domain_message "tessera.v1.message"

  @type key_material :: binary()
  @type derivation_path :: String.t()
  @type key :: RootKey.t() | ConversationKey.t() | EpochKey.t() | MessageKey.t()

  # ============================================================================
  # Root Key Generation
  # ============================================================================

  @doc """
  Generates a new cryptographically secure root key.

  The root key is the master key from which all other keys in the hierarchy
  are derived. It should be stored securely and never exposed.

  ## Options

  - `:entropy` - Optional additional entropy to mix into key generation

  ## Examples

      {:ok, root_key} = KeyDerivation.generate_root_key()
      {:ok, root_key} = KeyDerivation.generate_root_key(entropy: user_password_hash)
  """
  @spec generate_root_key(keyword()) :: {:ok, RootKey.t()}
  def generate_root_key(opts \\ []) do
    random_bytes = :crypto.strong_rand_bytes(@key_length)

    key_material =
      case Keyword.get(opts, :entropy) do
        nil ->
          random_bytes

        entropy when is_binary(entropy) ->
          hkdf_expand(
            hkdf_extract(random_bytes, entropy),
            @domain_root,
            @key_length
          )
      end

    {:ok, RootKey.new(key_material)}
  end

  @doc """
  Derives a root key from a password using PBKDF2.

  This is useful for password-based key derivation where the root key
  needs to be recoverable from a user's password.

  ## Options

  - `:salt` - Salt for PBKDF2 (required for security, generated if not provided)
  - `:iterations` - Number of PBKDF2 iterations (default: 100_000)

  ## Examples

      {:ok, root_key, salt} = KeyDerivation.derive_root_from_password("my-password")
      {:ok, root_key, ^salt} = KeyDerivation.derive_root_from_password("my-password", salt: salt)
  """
  @spec derive_root_from_password(String.t(), keyword()) :: {:ok, RootKey.t(), binary()}
  def derive_root_from_password(password, opts \\ []) when is_binary(password) do
    salt = Keyword.get(opts, :salt, :crypto.strong_rand_bytes(16))
    iterations = Keyword.get(opts, :iterations, 100_000)

    key_material = pbkdf2(password, salt, iterations, @key_length)

    {:ok, RootKey.new(key_material), salt}
  end

  # ============================================================================
  # Hierarchical Derivation
  # ============================================================================

  @doc """
  Derives a conversation key from a root key.

  Conversation keys are used to isolate different resource groups or
  conversations, providing compartmentalization.

  ## Examples

      {:ok, conv_key} = KeyDerivation.derive_conversation_key(root_key, "conversation-123")
  """
  @spec derive_conversation_key(RootKey.t(), String.t()) :: {:ok, ConversationKey.t()}
  def derive_conversation_key(%RootKey{} = root_key, conversation_id)
      when is_binary(conversation_id) do
    info = build_info(@domain_conversation, conversation_id)
    derived = hkdf_expand(root_key.material, info, @key_length)

    {:ok, ConversationKey.new(derived, conversation_id, root_key)}
  end

  @doc """
  Derives an epoch key from a conversation key.

  Epoch keys provide forward secrecy by rotating keys at defined intervals.
  Old epoch keys can be deleted to prevent decryption of historical data.

  ## Examples

      {:ok, epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 1)
      {:ok, epoch_key} = KeyDerivation.derive_epoch_key(conv_key, 42)
  """
  @spec derive_epoch_key(ConversationKey.t(), non_neg_integer()) :: {:ok, EpochKey.t()}
  def derive_epoch_key(%ConversationKey{} = conv_key, epoch_number)
      when is_integer(epoch_number) and epoch_number >= 0 do
    info = build_info(@domain_epoch, Integer.to_string(epoch_number))
    derived = hkdf_expand(conv_key.material, info, @key_length)

    {:ok, EpochKey.new(derived, epoch_number, conv_key)}
  end

  @doc """
  Derives a message key from an epoch key.

  Message keys are the leaf keys used for actual encryption of resources.
  Each resource should have its own unique message key.

  ## Examples

      {:ok, msg_key} = KeyDerivation.derive_message_key(epoch_key, "document-abc")
  """
  @spec derive_message_key(EpochKey.t(), String.t()) :: {:ok, MessageKey.t()}
  def derive_message_key(%EpochKey{} = epoch_key, resource_id) when is_binary(resource_id) do
    info = build_info(@domain_message, resource_id)
    derived = hkdf_expand(epoch_key.material, info, @key_length)

    {:ok, MessageKey.new(derived, resource_id, epoch_key)}
  end

  # ============================================================================
  # Path-Based Derivation
  # ============================================================================

  @doc """
  Derives a key using path notation.

  Path format: `m/conv/<conversation_id>/epoch/<epoch_number>/msg/<resource_id>`

  Partial paths are supported:
  - `m` - Returns the root key unchanged
  - `m/conv/<id>` - Returns conversation key
  - `m/conv/<id>/epoch/<n>` - Returns epoch key
  - `m/conv/<id>/epoch/<n>/msg/<id>` - Returns message key

  ## Examples

      {:ok, msg_key} = KeyDerivation.derive_path(root_key, "m/conv/abc/epoch/5/msg/doc-1")
      {:ok, epoch_key} = KeyDerivation.derive_path(root_key, "m/conv/abc/epoch/5")
      {:ok, conv_key} = KeyDerivation.derive_path(root_key, "m/conv/abc")
  """
  @spec derive_path(RootKey.t(), derivation_path()) :: {:ok, key()} | {:error, term()}
  def derive_path(%RootKey{} = root_key, path) when is_binary(path) do
    case parse_path(path) do
      {:ok, segments} ->
        derive_from_segments(root_key, segments)

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Returns the full derivation path for a key.

  ## Examples

      KeyDerivation.key_path(msg_key)
      # => "m/conv/abc123/epoch/5/msg/document-1"
  """
  @spec key_path(key()) :: String.t()
  def key_path(%RootKey{}), do: "m"
  def key_path(%ConversationKey{conversation_id: id}), do: "m/conv/#{id}"

  def key_path(%EpochKey{epoch_number: n, parent: parent}) do
    "#{key_path(parent)}/epoch/#{n}"
  end

  def key_path(%MessageKey{resource_id: id, parent: parent}) do
    "#{key_path(parent)}/msg/#{id}"
  end

  # ============================================================================
  # Key Export/Import
  # ============================================================================

  @doc """
  Exports a key's material for storage.

  **Security Warning**: The exported material is sensitive and should be
  encrypted before storage.

  ## Options

  - `:format` - Export format (`:raw` or `:base64`, default: `:base64`)
  """
  @spec export_key(key(), keyword()) :: {:ok, binary()}
  def export_key(key, opts \\ []) do
    format = Keyword.get(opts, :format, :base64)
    material = get_key_material(key)

    case format do
      :raw -> {:ok, material}
      :base64 -> {:ok, Base.encode64(material)}
    end
  end

  @doc """
  Imports a root key from exported material.

  ## Examples

      {:ok, root_key} = KeyDerivation.import_root_key(base64_material, format: :base64)
  """
  @spec import_root_key(binary(), keyword()) :: {:ok, RootKey.t()} | {:error, term()}
  def import_root_key(material, opts \\ []) do
    format = Keyword.get(opts, :format, :base64)

    case decode_material(material, format) do
      {:ok, decoded} when byte_size(decoded) == @key_length ->
        {:ok, RootKey.new(decoded)}

      {:ok, decoded} ->
        {:error, {:invalid_key_length, byte_size(decoded)}}

      {:error, _} = error ->
        error
    end
  end

  # ============================================================================
  # Key Comparison
  # ============================================================================

  @doc """
  Constant-time comparison of two keys.

  Prevents timing attacks when comparing key material.
  """
  @spec equal?(key(), key()) :: boolean()
  def equal?(key1, key2) do
    :crypto.hash_equals(get_key_material(key1), get_key_material(key2))
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp hkdf_extract(ikm, salt) do
    :crypto.mac(:hmac, @hash_algorithm, salt, ikm)
  end

  defp hkdf_expand(prk, info, length) when byte_size(prk) >= 32 do
    # HKDF-Expand as per RFC 5869
    # For 32-byte output with SHA-256, we only need one iteration
    :crypto.mac(:hmac, @hash_algorithm, prk, <<info::binary, 1::8>>)
    |> binary_part(0, length)
  end

  defp build_info(domain, context) do
    # Domain separation with length-prefixed context
    context_bytes = byte_size(context)
    <<domain::binary, 0, context_bytes::16, context::binary>>
  end

  defp pbkdf2(password, salt, iterations, key_length) do
    :crypto.pbkdf2_hmac(:sha256, password, salt, iterations, key_length)
  end

  defp parse_path(path) do
    parts = String.split(path, "/")

    case parts do
      ["m"] ->
        {:ok, []}

      ["m", "conv", conv_id] ->
        {:ok, [{:conversation, conv_id}]}

      ["m", "conv", conv_id, "epoch", epoch_str] ->
        case Integer.parse(epoch_str) do
          {epoch, ""} -> {:ok, [{:conversation, conv_id}, {:epoch, epoch}]}
          _ -> {:error, {:invalid_epoch, epoch_str}}
        end

      ["m", "conv", conv_id, "epoch", epoch_str, "msg", resource_id] ->
        case Integer.parse(epoch_str) do
          {epoch, ""} ->
            {:ok, [{:conversation, conv_id}, {:epoch, epoch}, {:message, resource_id}]}

          _ ->
            {:error, {:invalid_epoch, epoch_str}}
        end

      _ ->
        {:error, {:invalid_path, path}}
    end
  end

  defp derive_from_segments(root_key, []) do
    {:ok, root_key}
  end

  defp derive_from_segments(root_key, [{:conversation, id} | rest]) do
    {:ok, conv_key} = derive_conversation_key(root_key, id)
    derive_from_segments(conv_key, rest)
  end

  defp derive_from_segments(conv_key, [{:epoch, n} | rest]) do
    {:ok, epoch_key} = derive_epoch_key(conv_key, n)
    derive_from_segments(epoch_key, rest)
  end

  defp derive_from_segments(epoch_key, [{:message, id} | rest]) do
    {:ok, msg_key} = derive_message_key(epoch_key, id)
    derive_from_segments(msg_key, rest)
  end

  defp get_key_material(%RootKey{material: m}), do: m
  defp get_key_material(%ConversationKey{material: m}), do: m
  defp get_key_material(%EpochKey{material: m}), do: m
  defp get_key_material(%MessageKey{material: m}), do: m

  defp decode_material(material, :raw), do: {:ok, material}

  defp decode_material(material, :base64) do
    case Base.decode64(material) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64}
    end
  end
end
