run lambda { |env|
  path = env['PATH_INFO'] || '/'
  [200, { 'Content-Type' => 'text/plain; charset=utf-8' }, ["hello from rack index path=#{path}\n"]]
}
