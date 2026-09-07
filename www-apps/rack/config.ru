lambda { |env|
  path = env['PATH_INFO'] || '/'
  [200, { 'Content-Type' => 'text/plain' }, ["hello from rack path=#{path}\n"]]
}
