# frozen_string_literal: true

# nr-authz-radar stage S2 for Ruby (newrelic_rpm 10.x API).
# Sends resource.owner_match and authz.decision (shared/attribute-spec.md) and a pseudonymized enduser.id.
# Call check_ownership right after loading a resource by a client-supplied ID.
require 'openssl'

module AuthzRadar
  class OwnershipError < StandardError
    def initialize(msg = 'ownership check failed') = super
  end

  # One per request. Keeps owner_match sticky and lets deny win over allow.
  RequestState = Struct.new(:mismatch, :denied) do
    def initialize(mismatch = false, denied = false) = super
  end

  module_function

  def agent(nr)
    return nr if nr

    require 'newrelic_rpm'
    NewRelic::Agent
  end

  # 'u_' + 16 hex chars. Without a key nothing is sent (a plain hash can be brute-forced).
  def pseudonym(user_id, key)
    return nil if key.nil? || key.empty? || user_id.nil?

    'u_' + OpenSSL::HMAC.hexdigest('SHA256', key, user_id.to_s)[0, 16]
  end

  def set_user(user_id, key, nr: nil)
    value = pseudonym(user_id, key)
    agent(nr).set_user_id(value) if value
  end

  # enforce: false (observe) lets mismatches through so detection D01 shows real IDORs.
  # bypass_scope marks legitimate cross-owner access (e.g. 'admin:read') so D01 excludes it.
  def check_ownership(owner_id, current_user_id, state, enforce: true, bypass_scope: nil, nr: nil)
    api = agent(nr)
    match = !current_user_id.nil? && owner_id.to_s == current_user_id.to_s
    state.mismatch = true unless match
    api.add_custom_attributes('resource.owner_match' => !state.mismatch)
    if !match && bypass_scope
      api.add_custom_attributes('authz.required_scope' => bypass_scope)
    elsif !match && enforce
      state.denied = true
      api.add_custom_attributes('authz.decision' => 'deny')
      error = OwnershipError.new
      api.notice_error(error, expected: true) # grouped in Errors Inbox, not counted in error rate
      raise error
    end
    api.add_custom_attributes('authz.decision' => 'allow') unless state.denied
    match
  end
end
