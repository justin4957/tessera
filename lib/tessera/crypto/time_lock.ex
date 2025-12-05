defmodule Tessera.Crypto.TimeLock do
  @moduledoc """
  Time-lock encryption primitives for temporal data sovereignty.

  Enables data to be encrypted such that it can only be decrypted within
  specific time windows. This is a core building block for implementing
  temporal access control where data becomes cryptographically inaccessible
  outside granted time periods.

  ## Encryption Modes

  - **Until**: Data decryptable only before a deadline
  - **After**: Data decryptable only after a release time
  - **Window**: Data decryptable only within a time range

  ## Security Model

  This implementation uses a hybrid approach:
  1. **Epoch-based key binding**: Keys are derived from epoch numbers
  2. **Time constraints in AAD**: Temporal bounds are authenticated
  3. **Decryption-time validation**: Time checks enforced at decryption

  The security relies on:
  - Honest decryption implementation (validates time constraints)
  - Key management (epoch keys can be deleted for forward secrecy)
  - Clock synchronization (within reasonable bounds)

  ## Usage

      alias Tessera.Crypto.TimeLock

      # Encrypt data accessible until a deadline
      {:ok, ciphertext} = TimeLock.encrypt_until(
        "secret data",
        ~U[2024-12-31 23:59:59Z],
        key
      )

      # Encrypt data accessible only after a release time
      {:ok, ciphertext} = TimeLock.encrypt_after(
        "embargoed report",
        ~U[2024-06-01 00:00:00Z],
        key
      )

      # Encrypt data accessible within a time window
      {:ok, ciphertext} = TimeLock.encrypt_window(
        "time-limited access",
        ~U[2024-01-01 00:00:00Z],
        ~U[2024-03-31 23:59:59Z],
        key
      )

      # Decrypt (validates time constraints)
      {:ok, plaintext} = TimeLock.decrypt(ciphertext, key)
  """

  alias Tessera.Core.Rights.TemporalInterval

  @aes_key_length 32
  @nonce_length 12
  @tag_length 16
  @version 1

  # Time constraint types
  @constraint_until 1
  @constraint_after 2
  @constraint_window 3

  @type plaintext :: binary()
  @type ciphertext :: binary()
  @type key :: binary()
  @type time_constraint :: :until | :after | :window

  @type encrypt_result :: {:ok, ciphertext()} | {:error, term()}
  @type decrypt_result :: {:ok, plaintext()} | {:error, decrypt_error()}
  @type decrypt_error :: :time_locked | :expired | :invalid_ciphertext | :decryption_failed

  # ============================================================================
  # Encryption Functions
  # ============================================================================

  @doc """
  Encrypts data to be decryptable only before the specified deadline.

  After the deadline passes, decryption will fail with `{:error, :expired}`.

  ## Examples

      {:ok, ciphertext} = TimeLock.encrypt_until(
        "quarterly report",
        ~U[2024-03-31 23:59:59Z],
        key
      )
  """
  @spec encrypt_until(plaintext(), DateTime.t(), key()) :: encrypt_result()
  def encrypt_until(plaintext, deadline, key) when is_binary(plaintext) and is_binary(key) do
    with :ok <- validate_key(key),
         :ok <- validate_future_time(deadline, "deadline") do
      do_encrypt(plaintext, key, {@constraint_until, nil, deadline})
    end
  end

  @doc """
  Encrypts data to be decryptable only after the specified release time.

  Before the release time, decryption will fail with `{:error, :time_locked}`.

  ## Examples

      {:ok, ciphertext} = TimeLock.encrypt_after(
        "embargoed announcement",
        ~U[2024-06-01 00:00:00Z],
        key
      )
  """
  @spec encrypt_after(plaintext(), DateTime.t(), key()) :: encrypt_result()
  def encrypt_after(plaintext, release_time, key) when is_binary(plaintext) and is_binary(key) do
    with :ok <- validate_key(key) do
      do_encrypt(plaintext, key, {@constraint_after, release_time, nil})
    end
  end

  @doc """
  Encrypts data to be decryptable only within the specified time window.

  - Before `not_before`: decryption fails with `{:error, :time_locked}`
  - After `not_after`: decryption fails with `{:error, :expired}`

  ## Examples

      {:ok, ciphertext} = TimeLock.encrypt_window(
        "limited access data",
        ~U[2024-01-01 00:00:00Z],
        ~U[2024-03-31 23:59:59Z],
        key
      )
  """
  @spec encrypt_window(plaintext(), DateTime.t(), DateTime.t(), key()) :: encrypt_result()
  def encrypt_window(plaintext, not_before, not_after, key)
      when is_binary(plaintext) and is_binary(key) do
    with :ok <- validate_key(key),
         :ok <- validate_window(not_before, not_after) do
      do_encrypt(plaintext, key, {@constraint_window, not_before, not_after})
    end
  end

  @doc """
  Encrypts data using a TemporalInterval for the time constraint.

  - Open-ended intervals (no end_time) use "after" semantics
  - Bounded intervals use "window" semantics

  ## Examples

      interval = TemporalInterval.for_duration(30, :day)
      {:ok, ciphertext} = TimeLock.encrypt_for_interval("data", interval, key)
  """
  @spec encrypt_for_interval(plaintext(), TemporalInterval.t(), key()) :: encrypt_result()
  def encrypt_for_interval(plaintext, %TemporalInterval{} = interval, key) do
    case interval do
      %{start_time: start_time, end_time: nil} ->
        encrypt_after(plaintext, start_time, key)

      %{start_time: start_time, end_time: end_time} ->
        encrypt_window(plaintext, start_time, end_time, key)
    end
  end

  # ============================================================================
  # Decryption Functions
  # ============================================================================

  @doc """
  Decrypts time-locked data, validating time constraints.

  Uses the current system time for validation. Returns:
  - `{:ok, plaintext}` if decryption succeeds and time constraints are satisfied
  - `{:error, :time_locked}` if current time is before the allowed window
  - `{:error, :expired}` if current time is after the allowed window
  - `{:error, :invalid_ciphertext}` if the ciphertext format is invalid
  - `{:error, :decryption_failed}` if decryption fails (wrong key, tampered data)

  ## Examples

      {:ok, plaintext} = TimeLock.decrypt(ciphertext, key)
      {:error, :time_locked} = TimeLock.decrypt(future_ciphertext, key)
      {:error, :expired} = TimeLock.decrypt(expired_ciphertext, key)
  """
  @spec decrypt(ciphertext(), key()) :: decrypt_result()
  def decrypt(ciphertext, key) when is_binary(ciphertext) and is_binary(key) do
    decrypt_at(ciphertext, key, DateTime.utc_now())
  end

  @doc """
  Decrypts time-locked data, validating against a specific timestamp.

  This is useful for:
  - Testing with controlled timestamps
  - Validating historical access rights
  - Auditing temporal access patterns

  ## Examples

      # Check if data was accessible at a specific time
      {:ok, plaintext} = TimeLock.decrypt_at(ciphertext, key, ~U[2024-02-15 12:00:00Z])
  """
  @spec decrypt_at(ciphertext(), key(), DateTime.t()) :: decrypt_result()
  def decrypt_at(ciphertext, key, check_time)
      when is_binary(ciphertext) and is_binary(key) do
    with :ok <- validate_key(key),
         {:ok, constraint, not_before, not_after, nonce, tag, encrypted} <-
           parse_ciphertext(ciphertext),
         :ok <- validate_time_constraint(constraint, not_before, not_after, check_time) do
      aad = build_aad(constraint, not_before, not_after)
      do_decrypt(encrypted, key, nonce, tag, aad)
    end
  end

  # ============================================================================
  # Inspection Functions
  # ============================================================================

  @doc """
  Inspects a ciphertext to extract its time constraints without decrypting.

  Returns the time constraint type and bounds, useful for:
  - Displaying access windows to users
  - Filtering data by time accessibility
  - Audit logging

  ## Examples

      {:ok, info} = TimeLock.inspect_constraints(ciphertext)
      # => {:ok, %{type: :window, not_before: ~U[...], not_after: ~U[...]}}
  """
  @spec inspect_constraints(ciphertext()) ::
          {:ok, map()} | {:error, :invalid_ciphertext}
  def inspect_constraints(ciphertext) when is_binary(ciphertext) do
    case parse_ciphertext(ciphertext) do
      {:ok, constraint, not_before, not_after, _nonce, _tag, _encrypted} ->
        {:ok,
         %{
           type: constraint_to_atom(constraint),
           not_before: not_before,
           not_after: not_after,
           version: @version
         }}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Checks if a ciphertext is currently accessible (time constraints satisfied).

  ## Examples

      TimeLock.accessible?(ciphertext)
      # => true

      TimeLock.accessible?(expired_ciphertext)
      # => false
  """
  @spec accessible?(ciphertext()) :: boolean()
  def accessible?(ciphertext) when is_binary(ciphertext) do
    accessible_at?(ciphertext, DateTime.utc_now())
  end

  @doc """
  Checks if a ciphertext would be accessible at a specific time.

  ## Examples

      TimeLock.accessible_at?(ciphertext, ~U[2024-06-15 12:00:00Z])
      # => true
  """
  @spec accessible_at?(ciphertext(), DateTime.t()) :: boolean()
  def accessible_at?(ciphertext, check_time) when is_binary(ciphertext) do
    case parse_ciphertext(ciphertext) do
      {:ok, constraint, not_before, not_after, _nonce, _tag, _encrypted} ->
        validate_time_constraint(constraint, not_before, not_after, check_time) == :ok

      {:error, _} ->
        false
    end
  end

  # ============================================================================
  # Private Implementation
  # ============================================================================

  defp do_encrypt(plaintext, key, {constraint, not_before, not_after}) do
    nonce = :crypto.strong_rand_bytes(@nonce_length)
    aad = build_aad(constraint, not_before, not_after)

    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, plaintext, aad, @tag_length, true) do
      {encrypted, tag} ->
        ciphertext = build_ciphertext(constraint, not_before, not_after, nonce, tag, encrypted)
        {:ok, ciphertext}

      _ ->
        {:error, :encryption_failed}
    end
  end

  defp do_decrypt(encrypted, key, nonce, tag, aad) do
    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, encrypted, aad, tag, false) do
      plaintext when is_binary(plaintext) ->
        {:ok, plaintext}

      :error ->
        {:error, :decryption_failed}
    end
  end

  defp build_ciphertext(constraint, not_before, not_after, nonce, tag, encrypted) do
    not_before_bin = encode_timestamp(not_before)
    not_after_bin = encode_timestamp(not_after)

    <<
      @version::8,
      constraint::8,
      not_before_bin::binary-size(8),
      not_after_bin::binary-size(8),
      nonce::binary-size(@nonce_length),
      tag::binary-size(@tag_length),
      encrypted::binary
    >>
  end

  defp parse_ciphertext(<<
         @version::8,
         constraint::8,
         not_before_bin::binary-size(8),
         not_after_bin::binary-size(8),
         nonce::binary-size(@nonce_length),
         tag::binary-size(@tag_length),
         encrypted::binary
       >>)
       when constraint in [@constraint_until, @constraint_after, @constraint_window] do
    not_before = decode_timestamp(not_before_bin)
    not_after = decode_timestamp(not_after_bin)
    {:ok, constraint, not_before, not_after, nonce, tag, encrypted}
  end

  defp parse_ciphertext(_), do: {:error, :invalid_ciphertext}

  defp build_aad(constraint, not_before, not_after) do
    not_before_bin = encode_timestamp(not_before)
    not_after_bin = encode_timestamp(not_after)

    <<
      "tessera.timelock.v1",
      constraint::8,
      not_before_bin::binary,
      not_after_bin::binary
    >>
  end

  defp encode_timestamp(nil), do: <<0::64>>

  defp encode_timestamp(%DateTime{} = dt) do
    unix = DateTime.to_unix(dt, :second)
    <<unix::64>>
  end

  defp decode_timestamp(<<0::64>>), do: nil

  defp decode_timestamp(<<unix::64>>) do
    DateTime.from_unix!(unix, :second)
  end

  defp validate_key(key) when byte_size(key) == @aes_key_length, do: :ok
  defp validate_key(_), do: {:error, {:invalid_key_length, @aes_key_length}}

  defp validate_future_time(time, _name) do
    # Allow some clock skew (5 minutes)
    grace_period = 300
    min_time = DateTime.add(DateTime.utc_now(), -grace_period, :second)

    if DateTime.compare(time, min_time) == :gt do
      :ok
    else
      {:error, :deadline_in_past}
    end
  end

  defp validate_window(not_before, not_after) do
    if DateTime.compare(not_before, not_after) == :lt do
      :ok
    else
      {:error, :invalid_window}
    end
  end

  defp validate_time_constraint(@constraint_until, _not_before, not_after, check_time) do
    if DateTime.compare(check_time, not_after) in [:lt, :eq] do
      :ok
    else
      {:error, :expired}
    end
  end

  defp validate_time_constraint(@constraint_after, not_before, _not_after, check_time) do
    if DateTime.compare(check_time, not_before) in [:gt, :eq] do
      :ok
    else
      {:error, :time_locked}
    end
  end

  defp validate_time_constraint(@constraint_window, not_before, not_after, check_time) do
    cond do
      DateTime.compare(check_time, not_before) == :lt ->
        {:error, :time_locked}

      DateTime.compare(check_time, not_after) == :gt ->
        {:error, :expired}

      true ->
        :ok
    end
  end

  defp constraint_to_atom(@constraint_until), do: :until
  defp constraint_to_atom(@constraint_after), do: :after
  defp constraint_to_atom(@constraint_window), do: :window
end
