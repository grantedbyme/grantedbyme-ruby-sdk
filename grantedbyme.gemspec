# coding: utf-8
Gem::Specification.new do |s|
  s.name        = 'grantedbyme'
  s.version     = '1.0.9'
  s.summary     = 'GrantedByMe'
  s.description = 'GrantedByMe Ruby SDK'
  s.authors     = ['GrantedByMe']
  s.email       = 'info@grantedby.me'
  s.files       = ['lib/grantedbyme.rb',
                   'lib/grantedbyme/crypto.rb']
  s.homepage    = 'http://rubygems.org/gems/grantedbyme'
  s.license     = 'MIT'
  
  s.add_dependency 'minitest', '~> 0'
  s.add_dependency 'minitest-reporters', '~> 0'
  s.add_development_dependency 'rake', '~> 0'
  
end