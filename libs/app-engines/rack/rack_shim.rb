# Crucible Rack 兼容层 —— 编译进 libapp_rack.so（rack_shim_rb.h），不依赖运行时写文件。
#
# 目标机上的 libapp_rack.so 用进程内 MRI 嵌入加载 config.ru / index.ru。宿主装了
# rack gem 时优先用真正的 Rack::Builder.parse_file；没装（或真 Builder 处理不了
# 「裸 lambda」入口）时用这里的 Builder —— 覆盖 run / use / map 的最小子集：
#
#   run app                        # app 响应 call
#   run { |env| [status, {}, []] }
#   use Middleware, *args          # 先 use 的包在最外层（Rack 语义）
#   map '/prefix' do ... end       # 最长前缀匹配，改写 SCRIPT_NAME/PATH_INFO
#   裸 lambda { |env| ... }        # 文件最后一个表达式响应 call 时直接当 app
#
# 不提供的（需要真 rack gem）：Rack::Request/Response/Utils 等常量、Rack::Lint、
# hijack。取舍：目标机装 gem 可能没有网络，内置 Builder 保证 .ru 应用在无 rack
# 的宿主上也能真正服务（这是「curl /rack/ 返回 200 且正文来自 index.ru」的关键路径）。
#
# 失败语义：任何加载/调用异常都向上抛（由 rack_engine.c 用 rb_eval_string_protect
# 接住），异常消息/traceback 只进 out->error 供服务端日志，客户端只会看到固定文本。

module CrucibleRack
  # 响应体上限，与 C 侧/CGI 的 32MiB 约定一致；超过即截断并标注。
  MAX_BODY = 32 * 1024 * 1024

  # 无 stringio 时用的最小 rack.input（Rack SPEC 要求 gets/each/read/rewind）。
  class Input
    def initialize(str)
      @s = str.to_s.b
      @pos = 0
    end

    def gets
      return nil if @pos >= @s.bytesize

      nl = @s.index("\n", @pos)
      line = nl ? @s.byteslice(@pos, nl - @pos + 1) : @s.byteslice(@pos..-1)
      @pos += line.bytesize
      line
    end

    def read(len = nil, buf = nil)
      data = if len.nil?
               rest = @s.byteslice(@pos..-1) || ''.b
               @pos = @s.bytesize
               rest
             else
               out = @s.byteslice(@pos, len) || ''.b
               @pos += out.bytesize
               out
             end
      if buf
        buf.replace(data)
        buf
      else
        data
      end
    end

    def each
      return enum_for(:each) unless block_given?

      while (line = gets)
        yield line
      end
    end

    def rewind
      @pos = 0
      0
    end

    def close; end
  end

  # run/use/map 的最小 Rack::Builder 兼容实现。
  class Builder
    def initialize(&blk)
      @use = []
      @map = nil
      @run = nil
      @block_result = nil
      return unless blk

      ret = instance_eval(&blk)
      # 裸 lambda 入口（本目录 config.ru 的写法）：文件最后表达式是可调用对象。
      @block_result = ret if ret.respond_to?(:call)
    end

    def use(mw, *args, &blk)
      @use << [mw, args, blk]
      self
    end

    def run(app = nil, &blk)
      @run = blk || app
      self
    end

    def map(path, &blk)
      raise ArgumentError, 'map 需要 block' unless blk

      loc = path.to_s
      loc = loc.chomp('/') while loc.length > 1 && loc.end_with?('/')
      raise ArgumentError, "map location 必须以 / 开头（got #{loc.inspect}）" unless loc.start_with?('/')

      @map ||= {}
      @map[loc] = Builder.new(&blk).to_app
      self
    end

    def to_app
      base = @run || @block_result
      app = @map && !@map.empty? ? self.class.build_url_map(base, @map) : base
      # Rack 语义：@use 里先 use 的在外层，故反向注入。
      @use.reverse_each do |(mw, args, blk)|
        app = if mw.respond_to?(:new)
                blk ? mw.new(app, *args, &blk) : mw.new(app, *args)
              else
                mw.call(app, *args)
              end
      end
      raise 'missing run or map statement' if app.nil?

      app
    end

    # map 的最小子集（Rack::URLMap 语义）：最长前缀命中，重写 SCRIPT_NAME/PATH_INFO；
    # 无命中时回落 base（config.ru 里 run 的 app），没有 base 就 404。
    def self.build_url_map(base, map)
      routes = map.keys.sort_by { |p| -p.length }
      lambda do |env|
        path = env['PATH_INFO'].to_s
        hit = routes.find { |p| path == p || path.start_with?("#{p}/") }
        if hit.nil?
          if base
            base.call(env)
          else
            [404, { 'Content-Type' => 'text/plain; charset=utf-8' }, ['404 Not Found']]
          end
        else
          rest = path[hit.length..-1] || ''
          sub_env = env.merge(
            'SCRIPT_NAME' => env['SCRIPT_NAME'].to_s + hit,
            'PATH_INFO' => rest.empty? ? '/' : rest
          )
          map[hit].call(sub_env)
        end
      end
    end
  end

  # 与 Rack::Builder.new_from_string 等价：把源文件包进 Builder 的 block 再 eval，
  # 这样 run/use/map 的 self 是 Builder，而脚本里定义的常量仍在 Object 下。
  def self.eval_source(src, path)
    code = "CrucibleRack::Builder.new {\n#{src}\n}.to_app"
    eval(code, TOPLEVEL_BINDING, path.to_s, 0)
  end

  def self.eval_file(path)
    eval_source(File.read(path), path)
  end

  # rack gem 可用时优先真 Rack::Builder.parse_file（Rack 3 返回 [app, options]，
  # Rack 2 同样是数组）；真 Builder 对「裸 lambda」的 config.ru 会抛
  # "missing run or map statement" —— 此时回落内置 Builder 再试一次。
  def self.load_file(path)
    if defined?(::Rack::Builder) && ::Rack::Builder.respond_to?(:parse_file)
      begin
        r = ::Rack::Builder.parse_file(path)
        app = r.is_a?(::Array) ? r[0] : r
        return app if app.respond_to?(:call)
      rescue ::Exception
        # 故意吞掉，转内置 loader；真正的错误由 eval_file 抛出并进 out->error。
      end
    end
    eval_file(path)
  end

  def self.input_for(body)
    @input_class ||= begin
      require 'stringio'
      StringIO
    rescue LoadError, StandardError
      Input
    end
    @input_class.new(body)
  end

  # 每请求入口（由 C 侧 rb_eval_string_protect("CrucibleRack.dispatch($crucible_req)")）。
  # 返回 [status, headers_block, body, note_or_nil]；抛出的异常由 C 侧保护接住。
  # 这里自己 rescue 一次是为了**就地**格式化异常（消息+backtrace）写进
  # $crucible_last_error：C 侧在 protect 失败后虽然也能读 rb_errinfo，但自己再 eval
  # 格式化片段依赖更多 VM 状态，就地格式化最可靠。格式化失败也要保证有固定文本。
  def self.dispatch(req)
    $crucible_last_error = nil
    dispatch_inner(req)
  rescue Exception => e
    $crucible_last_error = format_exception(e)
    raise
  end

  def self.format_exception(e)
    bt = e.backtrace || []
    bt = bt.first(20) if bt.respond_to?(:first)
    "#{e.class}: #{e.message}\n#{bt.join("\n")}"
  rescue Exception => x
    "ruby exception (unprintable: #{x.class})"
  end

  def self.dispatch_inner(req)
    script = req['script'].to_s
    mtime = begin
      File.stat(script).mtime.to_f
    rescue SystemCallError
      nil
    end

    if @app.nil? || @app_script != script || @app_mtime != mtime
      app = load_file(script)
      raise "rack: #{script} 未返回可调用对象（#{app.class}）" unless app.respond_to?(:call)

      @app = app
      @app_script = script
      @app_mtime = mtime
    end
    app = @app

    body_in = req['body']
    body_in = ''.b if body_in.nil?
    method = (req['method'] || 'GET').to_s
    path = (req['path'] || '/').to_s
    port = (req['server_port'] || '80').to_s
    name = (req['server_name'] || 'crucible').to_s
    host = port.empty? || port == '80' ? name : "#{name}:#{port}"

    env = {
      'REQUEST_METHOD' => method,
      'SCRIPT_NAME' => '',
      'PATH_INFO' => path,
      'REQUEST_PATH' => path,
      'QUERY_STRING' => req['query'].to_s,
      'SERVER_NAME' => name,
      'SERVER_PORT' => port,
      'SERVER_PROTOCOL' => 'HTTP/1.1',
      'SERVER_SOFTWARE' => 'crucible/libapp_rack',
      'REMOTE_ADDR' => req['remote'].to_s,
      'CONTENT_TYPE' => req['content_type'].to_s,
      'CONTENT_LENGTH' => req['content_length'].to_s,
      'HTTP_HOST' => host,
      # Rack 2 SPEC 的版本数组；Rack 3 已不强制该键，中间件兼容起见保留。
      'rack.version' => [1, 3],
      'rack.url_scheme' => 'http',
      'rack.input' => input_for(body_in),
      'rack.errors' => $stderr,
      'rack.multithread' => false,
      'rack.multiprocess' => false,
      'rack.run_once' => false,
      'rack.hijack?' => false
    }

    # ABI 请求头块（每行 "Name: Value"，\r\n 分隔）→ env 的 HTTP_*（Rack/CGI 语义）。
    # Content-Type/Length 已有独立 env 键，跳过防覆盖；HTTP_HOST 会被请求的真实
    # Host 覆盖（上面的合成值只是缺 Host 时的回落）。
    hdrs = req['headers'].to_s
    unless hdrs.empty?
      hdrs.split("\r\n").each do |line|
        next if line.empty?

        k, sep, v = line.partition(':')
        next if sep.empty?

        k = k.strip
        v = v.strip
        next if k.empty?
        next if k.downcase == 'content-type' || k.downcase == 'content-length'

        ek = k.upcase.tr('-', '_')
        next unless ek.match?(/\A[A-Z0-9_.]+\z/)

        env["HTTP_#{ek}"] = v
      end
    end

    r = app.call(env)
    r = r.to_a if !r.is_a?(Array) && r.respond_to?(:to_a)
    raise "rack: 应用返回 #{r.class}（需要 [status, headers, body]）" unless r.is_a?(Array) && r.size >= 3

    status = r[0]
    headers = r[1]
    body = r[2]
    raise "rack: status 必须是 Integer（got #{status.class}）" unless status.is_a?(Integer)
    raise "rack: headers 必须是 Hash（got #{headers.class}）" unless headers.is_a?(Hash)

    hdr = ''.b
    headers.each do |k, v|
      name_s = k.to_s
      next if name_s.empty? || name_s.include?("\r") || name_s.include?("\n") || name_s.include?("\0")

      (v.is_a?(Array) ? v : [v]).each do |one|
        s = one.to_s
        next if s.include?("\r") || s.include?("\n") || s.include?("\0")

        hdr << name_s.b << ': '.b << s.b << "\r\n".b
      end
    end

    buf = ''.b
    truncated = false
    close_body = body.respond_to?(:close)
    begin
      if body.respond_to?(:each)
        body.each do |chunk|
          next if chunk.nil?

          buf << chunk.to_s.b
          if buf.bytesize > MAX_BODY
            buf = buf.byteslice(0, MAX_BODY)
            truncated = true
            break
          end
        end
      elsif body.respond_to?(:call)
        buf << body.call.to_s.b
        if buf.bytesize > MAX_BODY
          buf = buf.byteslice(0, MAX_BODY)
          truncated = true
        end
      elsif !body.nil?
        buf << body.to_s.b
      end
    ensure
      body.close if close_body
    end

    note = nil
    if truncated
      hdr << "X-Crucible-Truncated: 1\r\n".b
      note = "rack: 响应体超过 #{MAX_BODY} 字节上限，已截断（script=#{script}）"
    end
    [status, hdr, buf, note]
  end
end

# rack gem 可用则用真 Rack；否则补一个最小 Rack::Builder（只在本文件内提供
# parse_file/new_from_string，使 config.ru 里的 Rack::Builder.new { ... } 也能用）。
begin
  require 'rubygems'
rescue LoadError, StandardError
  nil
end
begin
  require 'rack'
  $crucible_have_rack = true
rescue LoadError, StandardError
  $crucible_have_rack = false
end

unless defined?(::Rack)
  module Rack
    class Builder < CrucibleRack::Builder
      def self.new_from_string(src, file = '(rackup)')
        CrucibleRack.eval_source(src, file)
      end

      def self.parse_file(path, _opts = nil)
        CrucibleRack.eval_file(path)
      end
    end
  end
end

$crucible_shim_ready = true
