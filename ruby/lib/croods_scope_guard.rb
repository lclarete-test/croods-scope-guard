# frozen_string_literal: true

# Load from a Rails initializer after the Croods gem has been loaded.
module CroodsScopeGuard
  class UnscopedResource < StandardError; end

  class << self
    # Explicit escape hatches are intentionally opt-in and should be reviewed.
    def global_models
      @global_models ||= []
    end

    def ownerless_models
      @ownerless_models ||= []
    end

    def allow_tenant_creation
      @allow_tenant_creation ||= false
    end

    attr_writer :allow_tenant_creation

    def install!
      raise LoadError, 'Load croods before CroodsScopeGuard.install!' unless defined?(::Croods::Policy::Scope)

      ::Croods::Policy::Scope.prepend(ScopeGuard) unless ::Croods::Policy::Scope.ancestors.include?(ScopeGuard)
    end
  end

  module ScopeGuard
    protected

    def tenant_scope(scope)
      model = scope.respond_to?(:klass) ? scope.klass : scope
      return scope if CroodsScopeGuard.global_models.include?(model.name)

      unless tenant
        raise UnscopedResource, "No current tenant for #{model.name}"
      end

      tenant_model = Croods.multi_tenancy_by.to_s.camelize.constantize
      if model == tenant_model
        if action.respond_to?(:name) && action.name.to_sym == :create
          return scope if CroodsScopeGuard.allow_tenant_creation

          raise UnscopedResource, "Creating #{model.name} requires an explicit tenant-creation policy"
        end

        # The tenant table usually has no foreign key pointing to itself.
        # Restrict reads/writes to the authenticated tenant by primary key.
        return scope.where(id: tenant.id)
      end

      if !scope.has_attribute?(Croods.tenant_attribute) &&
         reflection_path(scope, Croods.multi_tenancy_by).empty?
        raise UnscopedResource, "No tenant path from #{model.name} to #{tenant_model.name}"
      end

      super
    end

    def owner_scope(scope)
      model = scope.respond_to?(:klass) ? scope.klass : scope
      return scope if CroodsScopeGuard.ownerless_models.include?(model.name)

      if !user_owner_scope?(scope) && !immediate_owner_scope?(scope) &&
         reflection_path(scope, :user).empty?
        raise UnscopedResource, "No owner path for #{model.name}"
      end

      super
    end
  end
end
