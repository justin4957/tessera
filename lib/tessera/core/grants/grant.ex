defmodule Tessera.Core.Grants.Grant do
  @moduledoc """
  Represents a temporal access grant - the core primitive of Tessera's
  data sovereignty model.

  A Grant binds together:
  - A grantee (user receiving access)
  - A resource (data being accessed)
  - A temporal interval (when access is valid)
  - A scope (what operations are permitted)
  - Optional purpose binding (why access was granted)

  ## Example

      grant = Grant.new(
        grantee_id: "did:web:alice.example",
        resource_id: "pod://bob.example/medical/records",
        interval: TemporalInterval.for_duration(90, :day),
        scope: [:read],
        purpose: "insurance_claim_2024_q1"
      )

      # Later, revoke forward access
      {:ok, revoked_grant} = Grant.revoke(grant)
  """

  alias Tessera.Core.Rights.TemporalInterval

  @type scope :: :read | :write | :compute | :redact | :export

  @enforce_keys [:id, :grantee_id, :resource_id, :interval, :scope]
  defstruct [
    :id,
    :grantee_id,
    :resource_id,
    :interval,
    :scope,
    :purpose,
    :context,
    :frozen,
    :revoked_at,
    :created_at
  ]

  @type t :: %__MODULE__{
          id: String.t(),
          grantee_id: String.t(),
          resource_id: String.t(),
          interval: TemporalInterval.t(),
          scope: [scope()],
          purpose: String.t() | nil,
          context: map() | nil,
          frozen: boolean() | nil,
          revoked_at: DateTime.t() | nil,
          created_at: DateTime.t()
        }

  @doc """
  Creates a new grant with the given parameters.
  """
  @spec new(keyword()) :: t()
  def new(attrs) do
    %__MODULE__{
      id: Keyword.get(attrs, :id, generate_id()),
      grantee_id: Keyword.fetch!(attrs, :grantee_id),
      resource_id: Keyword.fetch!(attrs, :resource_id),
      interval: Keyword.fetch!(attrs, :interval),
      scope: Keyword.fetch!(attrs, :scope),
      purpose: Keyword.get(attrs, :purpose),
      context: Keyword.get(attrs, :context),
      frozen: false,
      revoked_at: nil,
      created_at: DateTime.utc_now()
    }
  end

  @doc """
  Revokes the grant at the current time.
  Historical access (before revocation) remains provable.
  """
  @spec revoke(t()) :: {:ok, t()} | {:error, :already_revoked | :frozen}
  def revoke(%__MODULE__{frozen: true}), do: {:error, :frozen}

  def revoke(%__MODULE__{revoked_at: revoked} = _grant) when not is_nil(revoked) do
    {:error, :already_revoked}
  end

  def revoke(%__MODULE__{} = grant) do
    now = DateTime.utc_now()
    {:ok, truncated_interval} = TemporalInterval.truncate_at(grant.interval, now)

    {:ok, %{grant | interval: truncated_interval, revoked_at: now}}
  end

  @doc """
  Extends the grant's temporal interval to a new end time.
  """
  @spec extend(t(), DateTime.t()) :: {:ok, t()} | {:error, term()}
  def extend(%__MODULE__{frozen: true}, _new_end), do: {:error, :frozen}

  def extend(%__MODULE__{revoked_at: revoked}, _new_end) when not is_nil(revoked) do
    {:error, :already_revoked}
  end

  def extend(%__MODULE__{interval: interval} = grant, new_end_time) do
    case TemporalInterval.extend(interval, new_end_time) do
      {:ok, new_interval} -> {:ok, %{grant | interval: new_interval}}
      error -> error
    end
  end

  @doc """
  Freezes the grant, preventing any future modifications.
  Creates an immutable snapshot for audit purposes.
  """
  @spec freeze(t()) :: {:ok, t()} | {:error, :already_frozen}
  def freeze(%__MODULE__{frozen: true}), do: {:error, :already_frozen}

  def freeze(%__MODULE__{} = grant) do
    {:ok, %{grant | frozen: true}}
  end

  @doc """
  Checks if the grant is currently active (valid at this moment).
  """
  @spec active?(t()) :: boolean()
  def active?(%__MODULE__{revoked_at: revoked}) when not is_nil(revoked), do: false

  def active?(%__MODULE__{interval: interval}) do
    TemporalInterval.active?(interval)
  end

  @doc """
  Checks if the grant was active at a specific point in time.
  """
  @spec active_at?(t(), DateTime.t()) :: boolean()
  def active_at?(%__MODULE__{revoked_at: nil, interval: interval}, datetime) do
    TemporalInterval.contains?(interval, datetime)
  end

  def active_at?(%__MODULE__{revoked_at: revoked_at, interval: interval}, datetime) do
    TemporalInterval.contains?(interval, datetime) and
      DateTime.compare(datetime, revoked_at) == :lt
  end

  @doc """
  Checks if the grant permits a specific operation.
  """
  @spec permits?(t(), scope()) :: boolean()
  def permits?(%__MODULE__{scope: scopes}, operation) do
    operation in scopes
  end

  @doc """
  Returns a constrained version of the grant with reduced scope.
  """
  @spec constrain_scope(t(), [scope()]) :: {:ok, t()} | {:error, :invalid_scope}
  def constrain_scope(%__MODULE__{frozen: true}, _new_scope), do: {:error, :frozen}

  def constrain_scope(%__MODULE__{scope: current_scope} = grant, new_scope) do
    if Enum.all?(new_scope, &(&1 in current_scope)) do
      {:ok, %{grant | scope: new_scope}}
    else
      {:error, :invalid_scope}
    end
  end

  @doc """
  Creates a temporal slice of the grant for audit purposes.
  """
  @spec slice(t(), TemporalInterval.t()) :: {:ok, t()} | {:error, :no_overlap}
  def slice(%__MODULE__{interval: interval} = grant, slice_interval) do
    case TemporalInterval.slice(interval, slice_interval) do
      {:ok, sliced_interval} ->
        {:ok, %{grant | interval: sliced_interval, frozen: true}}

      error ->
        error
    end
  end

  # Private helpers

  defp generate_id do
    :crypto.strong_rand_bytes(16)
    |> Base.url_encode64(padding: false)
  end
end
