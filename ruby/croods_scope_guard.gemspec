# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = 'croods_scope_guard'
  spec.version = '0.1.0'
  spec.summary = 'Fail-closed tenant and owner scoping for croods-rails'
  spec.description = 'Opt-in Rails runtime guard for missing Croods authorization paths.'
  spec.authors = ['Croods Scope Guard contributors']
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 2.7.6'
  spec.files = ['lib/croods_scope_guard.rb', 'README.md', 'LICENSE']
  spec.require_paths = ['lib']
end
