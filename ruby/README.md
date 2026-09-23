# Croods Scope Guard (Ruby component)

This opt-in runtime guard patches `Croods::Policy::Scope` using `prepend`.

In a Rails project using Croods, add to `Gemfile`:

```ruby
gem 'croods_scope_guard', path: '/path/to/croods-scope-guard/ruby'
```

After `bundle install`, put this in a Rails initializer that runs after Croods loads:

```ruby
require 'croods_scope_guard'
CroodsScopeGuard.install!
```

If a model is truly shared across tenants, explicitly opt it out **before** calling `install!`:

```ruby
CroodsScopeGuard.global_models << 'PublicCatalog'
```

If a model intentionally has no owner and Croods applies the `:owner` role, review
the policy first. Only then explicitly opt it out:

```ruby
CroodsScopeGuard.ownerless_models << 'PublicCatalog'
```

The tenant model (for example `Organization` when `multi_tenancy_by: :organization`)
is filtered by its own ID for lookup actions. Creating a new tenant through a
Croods endpoint raises by default, because a `where(id: ...)` scope would set a
primary key on a new row. Use a dedicated onboarding action or, after reviewing
its authorization, set `CroodsScopeGuard.allow_tenant_creation = true`.

An unmatched required scope raises `CroodsScopeGuard::UnscopedResource`.
Your application should translate this internal configuration error to a generic
HTTP 500 and avoid echoing model details to clients. Enable in a staging app first
and add two-tenant request specs before rolling into production.

This is an optional guard, not a change to the upstream Croods repository.
