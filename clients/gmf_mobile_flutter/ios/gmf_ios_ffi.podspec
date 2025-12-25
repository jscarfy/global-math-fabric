Pod::Spec.new do |s|
  s.name             = 'gmf_ios_ffi'
  s.version          = '0.1.0'
  s.summary          = 'GMF iOS Rust FFI'
  s.license          = { :type => 'MIT' }
  s.author           = { 'GMF' => 'gmf@local' }
  s.homepage         = 'https://example.invalid'
  s.source           = { :path => '.' }
  s.platform         = :ios, '12.0'
  s.vendored_frameworks = 'Runner/ffi/gmf_ios_ffi.xcframework'
  s.public_header_files = 'Runner/ffi/*.h'
end
