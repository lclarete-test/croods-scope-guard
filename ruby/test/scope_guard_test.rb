# frozen_string_literal: true

# Standalone smoke tests: ruby -I ruby/lib ruby/test/scope_guard_test.rb
require 'minitest/autorun'
require_relative '../lib/croods_scope_guard'

class String
  def camelize
    split('_').map(&:capitalize).join
  end

  def constantize
    Object.const_get(self)
  end
end

class Organization
  def self.where(filters)
    filters
  end

  def self.has_attribute?(_attribute)
    false
  end
end

class Invoice
  def self.has_attribute?(_attribute)
    false
  end
end

module Croods
  def self.multi_tenancy_by
    :organization
  end

  def self.tenant_attribute
    :organization_id
  end

  class Policy
    class Scope
      def initialize(tenant, action)
        @tenant = tenant
        @action = action
      end

      protected

      attr_reader :tenant, :action

      def tenant_scope(scope)
        scope
      end

      def owner_scope(scope)
        scope
      end

      def reflection_path(_scope, _target)
        []
      end

      def user_owner_scope?(_scope)
        false
      end

      def immediate_owner_scope?(_scope)
        false
      end
    end
  end
end

class ScopeGuardTest < Minitest::Test
  def setup
    CroodsScopeGuard.global_models.clear
    CroodsScopeGuard.ownerless_models.clear
    CroodsScopeGuard.allow_tenant_creation = false
    CroodsScopeGuard.install!
    @tenant = Struct.new(:id).new(42)
  end

  def scope(action = :index)
    Croods::Policy::Scope.new(@tenant, Struct.new(:name).new(action))
  end

  def test_tenant_root_is_filtered_by_id
    assert_equal({ id: 42 }, scope.send(:tenant_scope, Organization))
  end

  def test_missing_tenant_path_raises
    assert_raises(CroodsScopeGuard::UnscopedResource) { scope.send(:tenant_scope, Invoice) }
  end

  def test_creation_of_tenant_requires_explicit_policy
    assert_raises(CroodsScopeGuard::UnscopedResource) { scope(:create).send(:tenant_scope, Organization) }
  end

  def test_missing_owner_path_raises
    assert_raises(CroodsScopeGuard::UnscopedResource) { scope.send(:owner_scope, Invoice) }
  end

  def test_explicit_global_model_can_be_allowed
    CroodsScopeGuard.global_models << 'Invoice'
    assert_equal Invoice, scope.send(:tenant_scope, Invoice)
  end
end
