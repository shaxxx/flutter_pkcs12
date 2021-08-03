#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint flutter_pkcs12.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'flutter_pkcs12'
  s.version          = '0.0.1'
  s.summary          = 'Plugin to digitally sign data with PKCS12 certificates.'
  s.description      = <<-DESC
  Plugin to digitally sign data with PKCS12 certificates.
                       DESC
  s.homepage         = 'https://github.com/shaxxx/flutter_pkcs12'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Integrator Dubrovnik' => 'integrator@integrator.hr' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'FlutterMacOS'

  s.platform = :osx, '10.12'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
