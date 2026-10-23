# frozen_string_literal: true

require 'minitest/autorun'
require_relative 'authz_radar'

class FakeAgent
  attr_reader :attrs, :errors, :user

  def initialize = (@attrs, @errors, @user = {}, 0, nil)
  def add_custom_attributes(h) = @attrs.merge!(h)
  def notice_error(_e, expected: false) = (@errors += 1 if expected)
  def set_user_id(v) = (@user = v)
end

class AuthzRadarTest < Minitest::Test
  def setup
    @nr = FakeAgent.new
    @state = AuthzRadar::RequestState.new
  end

  def test_owner_is_allowed
    assert AuthzRadar.check_ownership('alice', 'alice', @state, nr: @nr)
    assert_equal({ 'resource.owner_match' => true, 'authz.decision' => 'allow' }, @nr.attrs)
  end

  def test_mismatch_is_denied_in_enforce_mode
    assert_raises(AuthzRadar::OwnershipError) { AuthzRadar.check_ownership('bob', 'alice', @state, nr: @nr) }
    assert_equal({ 'resource.owner_match' => false, 'authz.decision' => 'deny' }, @nr.attrs)
    assert_equal 1, @nr.errors
  end

  def test_observe_mode_is_sticky
    AuthzRadar.check_ownership('bob', 'alice', @state, enforce: false, nr: @nr)
    AuthzRadar.check_ownership('alice', 'alice', @state, enforce: false, nr: @nr)
    assert_equal({ 'resource.owner_match' => false, 'authz.decision' => 'allow' }, @nr.attrs)
  end

  def test_bypass_is_labelled
    AuthzRadar.check_ownership('bob', 'ops', @state, bypass_scope: 'admin:read', nr: @nr)
    assert_equal 'admin:read', @nr.attrs['authz.required_scope']
  end

  def test_user_is_pseudonymized
    AuthzRadar.set_user('alice', 'k', nr: @nr)
    assert_match(/\Au_[0-9a-f]{16}\z/, @nr.user)
    assert_nil AuthzRadar.pseudonym('alice', '')
  end
end
