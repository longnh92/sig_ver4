require "./lib/aws/version"

Gem::Specification.new do |s|
  s.name          = 'sig_ver4'
  s.version       = Aws::SIG_VER4_GEM_VERSION
  s.summary       = "Generate request headers with AWS Signature version 4"
  s.description   = "Generate request headers with AWS Signature version 4"
  s.authors       = ["Long Nguyen"]
  s.email         = ["longnh92@gmail.com"]
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- test/*`.split("\n")
  s.require_paths = ["lib"]
  s.homepage      = 'http://github.com/longnh92/sig_ver4'
  s.license       = 'MIT'
end
