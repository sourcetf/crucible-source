#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Crucible Rack app engine — 常驻 sidecar（Unix domain socket 上的 HTTP/1.1）。
#
# 为什么不是「进程内嵌入 MRI」：OpenBSD 上把 MRI 嵌入多线程宿主进程会在 boot/请求期
# 崩掉整个 webserver（见 libs/app-engines/rack/rack_engine.c 与
# scripts/build_script_ffi.sh 的说明），因此该平台默认关闭嵌入，只产出「诚实失败」
# stub .so。旧的 `/ruby/` 已用常驻 sidecar 解决同一问题；本文件把同一方案给 `/rack/`：
# **一次拉起、长期驻留**（不是 per-request spawn，不是 CGI），崩溃只影响这个子进程，
# webserver 会在下一次请求时重新拉起。
#
# 与 `www-apps/ruby/sidecar.rb` 的协议保持一致：
#   WEBSERVER_LISTEN_UNIX   socket 路径（宿主生成）
#   DOCUMENT_ROOT           docroot（宿主以 current_dir + DOCUMENT_ROOT 给出）
#   WEBSERVER_APP_PREFIXES  逗号分隔的路由前缀（转发前已由宿主剥掉，这里兜底再剥一次）
#
# 请求 → 在同一进程内加载 docroot 下的 Rack 应用（config.ru / index.ru，经
# Rack::Builder 或内置兼容层），构造 CGI 语义 Rack env（HTTP_*、REQUEST_METHOD、
# PATH_INFO、QUERY_STRING、CONTENT_TYPE/LENGTH、REMOTE_ADDR）、body 进 rack.input，
# 调用 app.call(env)，把 [status, headers, body] 写回 HTTP/1.1 响应（keep-alive 复用
# 连接）。普通 `.rb` CGI 脚本（非 Rack）作为兼容路径执行：stdin=body、捕获 stdout、
# 解析 `Content-Type:`/`Status:` 头块。
#
# 失败语义：应用异常 → 客户端拿 500 + 错误 id + **已脱敏**（不含绝对路径）的异常
# 摘要；完整消息/backtrace 只进 sidecar 日志（宿主重定向到 state/native/*/sidecar.log）。
#
# `.env`：受管 sidecar 由宿主在 spawn 时注入进程环境（native_http::ensure_sidecar 的
# apply_clean_env）；显式 socket 场景没有这条通道，宿主会按请求发
# `x-crucible-env-<key>`（percent-encoded 值）—— 这里在调用应用期间临时写入 ENV，
# 并用一把进程级锁避免并发请求互相看到对方的键。

require 'socket'
require 'stringio'

SOCK = ENV['WEBSERVER_LISTEN_UNIX'] || ARGV[0] || 'state/rack/app.sock'
DOCROOT = File.expand_path(ENV['DOCUMENT_ROOT'] || ARGV[1] || Dir.pwd)
PREFIXES = (ENV['WEBSERVER_APP_PREFIXES'] || '').split(',').map(&:strip).reject(&:empty?)
# 与宿主配置的 `index = "index.ru"` 对应；config.ru 是 rackup 约定的兜底。
DEFAULT_INDEXES = [ENV['RACK_INDEX'], 'index.ru', 'config.ru'].compact.reject(&:empty?).uniq
MAX_BODY = 32 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADER_LINES = 128
MAX_LINE_BYTES = 16 * 1024
IO_TIMEOUT = (ENV['RACK_SIDECAR_TIMEOUT_SECS'] || '30').to_i

# 同一进程内的 ENV 变更（x-crucible-env-* / CGI 脚本）必须串行：ENV 是进程级的。
ENV_LOCK = Mutex.new
# Rack 应用加载/缓存（mtime 变化时重建）。MRI GVL 之外没有别的共享状态。
LOAD_LOCK = Mutex.new
APP_CACHE = {}

def log(msg)
  warn("rack-sidecar: #{msg}")
end

class HttpError < StandardError
  attr_reader :status

  def initialize(status, message)
    @status = status
    super(message)
  end
end

# 文件是普通 .rb 且不是 Rack 应用（没有 run/map）时，走 CGI 兼容路径。
class NotRackApp < StandardError; end

# ---------------------------------------------------------------- Rack 兼容层
#
# 目标机可能没有 rack gem（OpenBSD 的 pkg_add ruby34 不带 gem）。这里提供与
# libs/app-engines/rack/rack_shim.rb 相同语义的最小子集：run / use / map /
# 裸 lambda 入口。装了 rack gem 时优先用真正的 Rack::Builder.parse_file。
module CrucibleRack
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

  class Builder
    def initialize(&blk)
      @use = []
      @map = nil
      @run = nil
      @block_result = nil
      return unless blk

      ret = instance_eval(&blk)
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

    def map(loc_path, &blk)
      raise ArgumentError, 'map 需要 block' unless blk

      loc = loc_path.to_s
      loc = loc.chomp('/') while loc.length > 1 && loc.end_with?('/')
      raise ArgumentError, "map location 必须以 / 开头（got #{loc.inspect}）" unless loc.start_with?('/')

      @map ||= {}
      @map[loc] = Builder.new(&blk).to_app
      self
    end

    def to_app
      app = @run || @block_result
      app = self.class.build_url_map(app, @map) if @map && !@map.empty?
      @use.reverse_each do |(mw, args, blk)|
        app = if mw.respond_to?(:new)
                blk ? mw.new(app, *args, &blk) : mw.new(app, *args)
              else
                mw.call(app, *args)
              end
      end
      raise NotRackApp, 'missing run or map statement' if app.nil?

      app
    end

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

    def self.new_from_string(src, file = '(rackup)')
      eval_source(src, file)
    end

    def self.parse_file(path, _opts = nil)
      eval_file(path)
    end

    # 与 Rack::Builder.new_from_string 等价：run/use/map 的 self 是 Builder。
    def self.eval_source(src, path)
      code = "CrucibleRack::Builder.new {\n#{src}\n}.to_app"
      eval(code, TOPLEVEL_BINDING, path.to_s, 0)
    end

    def self.eval_file(path)
      eval_source(File.read(path), path)
    end
  end
end

# rack gem 可用则用真 Rack：其 parse_file 能正确处理标准 config.ru；没有 gem 时把
# 最小 Builder 挂到 Rack 常量下，让应用里的 Rack::Builder.new { ... } 也能工作。
begin
  require 'rubygems'
rescue LoadError, StandardError
  nil
end
begin
  require 'rack'
  HAVE_RACK_GEM = true
rescue LoadError, StandardError
  HAVE_RACK_GEM = false
end
unless defined?(::Rack)
  module Rack
    class Builder < CrucibleRack::Builder; end
  end
end

# ---------------------------------------------------------------- 工具函数

def percent_decode(str)
  s = str.to_s.b
  out = ''.b
  i = 0
  while i < s.bytesize
    c = s.getbyte(i)
    if c == 37 && i + 2 < s.bytesize # '%'
      h = s.byteslice(i + 1, 2)
      if h =~ /\A[0-9A-Fa-f]{2}\z/
        out << h.to_i(16).chr
        i += 3
        next
      end
    end
    out << c.chr
    i += 1
  end
  out
end

# 剥路由前缀（宿主已剥；这里对「直接对 socket 说话」的调用兜底）。
def app_relative(path)
  p = path.to_s
  PREFIXES.each do |pre|
    pre = pre.chomp('/')
    next if pre.empty?

    if p == pre
      return '/'
    elsif p.start_with?("#{pre}/")
      return p[pre.length..]
    end
  end
  p
end

def under_docroot?(real_path)
  real_root = begin
    File.realpath(DOCROOT)
  rescue SystemCallError
    DOCROOT
  end
  real_path == real_root || real_path.start_with?(real_root + File::SEPARATOR)
end

# 选要执行的文件：
#   * 请求路径直接命中 docroot 下的 .ru/.rb 文件 → 用它；
#   * 命中目录 → 目录里的 index.ru/config.ru；
#   * 其余（Rack 应用的常规路由）→ docroot/index.ru，再退 config.ru。
# 所有候选都做词法 + realpath 两道作用域校验（防 `..` / 符号链接逃逸）。
def resolve_app_file(rel)
  base = rel.to_s
  base = '/' if base.empty?
  rel_file = base.sub(%r{\A/+}, '')
  candidates = []
  if !rel_file.empty?
    full = File.expand_path(File.join(DOCROOT, rel_file))
    if full == DOCROOT || full.start_with?(DOCROOT + File::SEPARATOR)
      if File.directory?(full)
        DEFAULT_INDEXES.each { |idx| candidates << File.join(full, idx) }
      elsif File.file?(full) && (full.end_with?('.ru') || full.end_with?('.rb'))
        # 显式请求的文件必须真的在 docroot 内（realpath 校验）：符号链接逃逸时
        # **不**回落到默认应用，直接当作不存在（404），避免“请求 A、执行 B”。
        real = begin
          File.realpath(full)
        rescue SystemCallError
          nil
        end
        return nil unless real && under_docroot?(real)

        candidates << full
      end
    end
  end
  DEFAULT_INDEXES.each { |idx| candidates << File.join(DOCROOT, idx) }

  candidates.each do |path|
    next unless File.file?(path)

    real = begin
      File.realpath(path)
    rescue SystemCallError
      nil
    end
    next unless real && under_docroot?(real)

    return path
  end
  nil
end

# ---------------------------------------------------------------- 应用加载

def load_rack_app(path)
  if HAVE_RACK_GEM && defined?(::Rack::Builder) && ::Rack::Builder.respond_to?(:parse_file)
    begin
      r = ::Rack::Builder.parse_file(path)
      app = r.is_a?(Array) ? r[0] : r
      return app if app.respond_to?(:call)
    rescue Exception => e # rubocop:disable Lint/RescueException
      # 真 Builder 对「裸 lambda」会抛 missing run/map：这是本仓库 config.ru 的
      # 写法，交给下面的内置 Builder 再试一次。其它错误最终由内置 loader 重新
      # 抛出（带同样的消息/backtrace），不会丢诊断信息。
      raise NotRackApp, e.message if path.end_with?('.rb') && e.message.to_s.include?('missing run or map')
    end
  end
  app = CrucibleRack::Builder.eval_file(path)
  unless app.respond_to?(:call)
    raise NotRackApp, "rack: #{File.basename(path)} 未返回可调用对象（#{app.class}）"
  end

  app
end

def app_for(path)
  st = begin
    File.stat(path)
  rescue SystemCallError
    nil
  end
  stamp = st ? [st.mtime.to_f, st.size] : nil
  LOAD_LOCK.synchronize do
    cached = APP_CACHE[path]
    return cached[1] if cached && cached[0] == stamp && cached[1]

    app = load_rack_app(path)
    APP_CACHE[path] = [stamp, app]
    app
  end
end

# ---------------------------------------------------------------- CGI 兼容路径

# 普通 .rb 脚本（非 Rack）：CGI 语义 ENV + stdin=body + 捕获 stdout。
# 只在 ENV_LOCK 内执行（会临时改写进程 ENV / $stdin / $stdout）。
def run_cgi_script(script, req, path_info)
  overrides = cgi_env_overrides(req, path_info)
  out = StringIO.new
  old_out = $stdout
  old_in = $stdin
  old_prog = $PROGRAM_NAME
  ENV_LOCK.synchronize do
    saved = {}
    overrides.each_key { |k| saved[k] = ENV[k] }
    begin
      overrides.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
      $stdout = out
      $stdin = StringIO.new(req[:body])
      $PROGRAM_NAME = script
      load script
    ensure
      $stdout = old_out
      $stdin = old_in
      $PROGRAM_NAME = old_prog
      saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    end
  end
  status, headers, body = split_cgi_response(200, out.string)
  [status, headers, body]
end

def cgi_env_overrides(req, path_info)
  env = {
    'REQUEST_METHOD' => req[:method],
    'PATH_INFO' => path_info,
    'QUERY_STRING' => req[:query].to_s,
    'REMOTE_ADDR' => remote_addr(req),
    'GATEWAY_INTERFACE' => 'CGI/1.1',
    'SERVER_SOFTWARE' => 'crucible/rack-sidecar',
    'SCRIPT_NAME' => '',
    'CONTENT_LENGTH' => req[:body].bytesize.to_s
  }
  env['CONTENT_TYPE'] = req[:headers]['content-type'] if req[:headers]['content-type']
  # 清掉上一次请求可能残留的 HTTP_*，再写入本次的。
  ENV.each_key { |k| env[k] = nil if k.start_with?('HTTP_') }
  req[:headers].each do |k, v|
    next if k == 'content-type' || k == 'content-length'
    next if k.start_with?('x-crucible-env-') || k == 'x-crucible-rack-path'

    ek = k.upcase.tr('-', '_')
    env["HTTP_#{ek}"] = v if ek.match?(/\A[A-Z0-9_]+\z/)
  end
  env
end

# CGI 头块：只有明确出现 Content-Type / Status 才当头部，否则整体是正文
# （避免把恰好含冒号的正文误判成头）。
def split_cgi_response(default_status, raw)
  head, sep, rest = raw.partition(/\r?\n\r?\n/)
  unless sep.empty?
    status = default_status
    headers = []
    has_marker = false
    head.split(/\r?\n/).each do |line|
      k, v = line.split(':', 2)
      next if v.nil?

      key = k.strip
      val = v.strip
      case key.downcase
      when 'status'
        has_marker = true
        status = val.split(' ', 2).first.to_i
      when 'content-type'
        has_marker = true
        headers << [key, val]
      when 'content-length', 'connection', 'transfer-encoding'
        next
      else
        headers << [key, val]
      end
    end
    return [status, headers, rest] if has_marker
  end
  [default_status, [['Content-Type', 'text/plain; charset=utf-8']], raw]
end

# ---------------------------------------------------------------- 请求 / 响应

def read_line(io)
  line = io.gets("\n", MAX_LINE_BYTES + 1)
  return nil if line.nil?
  if line.bytesize > MAX_LINE_BYTES
    raise HttpError.new(431, 'request line/header too long')
  end

  line.chomp("\r\n")
end

def read_exact(io, len)
  return ''.b if len <= 0

  buf = ''.b
  while buf.bytesize < len
    chunk = io.read(len - buf.bytesize)
    raise HttpError.new(400, 'truncated request body') if chunk.nil? || chunk.empty?

    buf << chunk
  end
  buf
end

def read_chunked(io, limit)
  body = ''.b
  loop do
    line = read_line(io)
    raise HttpError.new(400, 'bad chunk header') if line.nil?

    size_hex = line.split(';', 2).first.to_s.strip
    raise HttpError.new(400, 'bad chunk size') unless size_hex.match?(/\A[0-9A-Fa-f]+\z/)

    size = size_hex.to_i(16)
    if size.zero?
      # trailer
      loop do
        t = read_line(io)
        break if t.nil? || t.empty?
      end
      break
    end
    raise HttpError.new(413, 'request body too large') if body.bytesize + size > limit

    body << read_exact(io, size)
    crlf = read_line(io)
    raise HttpError.new(400, 'bad chunk terminator') unless crlf == ''
  end
  body
end

def read_request(io)
  line = read_line(io)
  return nil if line.nil? || line.empty?

  method, target, ver = line.split(' ', 3)
  raise HttpError.new(400, 'malformed request line') if method.nil? || target.nil?
  raise HttpError.new(400, 'unsupported method token') unless method.match?(/\A[A-Za-z!#$%&'*+.^_`|~-]+\z/)

  headers = {}
  total = line.bytesize
  count = 0
  while (h = read_line(io))
    break if h.empty?

    total += h.bytesize
    count += 1
    raise HttpError.new(431, 'headers too large') if total > MAX_HEADER_BYTES || count > MAX_HEADER_LINES

    k, v = h.split(':', 2)
    next if k.nil? || k.strip.empty?

    key = k.strip.downcase
    val = v.to_s.strip
    headers[key] = headers.key?(key) ? "#{headers[key]}, #{val}" : val
  end

  body = if headers['transfer-encoding'].to_s.downcase.include?('chunked')
           read_chunked(io, MAX_BODY)
         else
           len = headers['content-length'].to_s.strip
           len = '0' if len.empty?
           raise HttpError.new(400, 'bad Content-Length') unless len.match?(/\A[0-9]+\z/)

           n = len.to_i
           raise HttpError.new(413, 'request body too large') if n > MAX_BODY

           read_exact(io, n)
         end

  raw_path, query = target.split('?', 2)
  # absolute-form（`GET http://host/path HTTP/1.1`）：origin server 只取 path。
  raw_path = raw_path.sub(%r{\A[A-Za-z][A-Za-z0-9+.-]*://[^/]*}, '')
  raw_path = '/' if raw_path.nil? || raw_path.empty?

  conn = headers['connection'].to_s.downcase.split(',').map(&:strip)
  keep_alive = if ver.to_s.upcase == 'HTTP/1.0'
                 conn.include?('keep-alive')
               else
                 !conn.include?('close')
               end

  {
    method: method.upcase,
    raw_path: raw_path,
    query: query.to_s,
    headers: headers,
    body: body,
    version: (ver || 'HTTP/1.1'),
    keep_alive: keep_alive
  }
end

def remote_addr(req)
  xff = req[:headers]['x-forwarded-for'].to_s.split(',').first.to_s.strip
  return xff unless xff.empty?

  ENV['REMOTE_ADDR'] || '127.0.0.1'
end

# 请求的应用相对路径（Rack 的 PATH_INFO 输入）。
#
# 宿主会把目录请求的代理目标改写成配置的 index（`/rack/` → `/index.ru`），这对
# PHP/CGI 正确、对 Rack 错误。宿主因此额外发内部头 `x-crucible-rack-path`
# （percent-encoded 的原始应用相对路径，客户端值已由宿主删除后重写）；
# 直接对 socket 说话（无宿主）时退回代理目标 + 剥前缀。
def request_path(req)
  raw = req[:headers]['x-crucible-rack-path'].to_s
  path = if raw.empty?
           app_relative(req[:raw_path])
         else
           percent_decode(raw)
         end
  path = '/' if path.empty?
  path
end

def build_rack_env(req, path_info)
  host = req[:headers]['host'].to_s
  name, port = host.split(':', 2)
  name = 'crucible' if name.nil? || name.empty?
  port = '80' if port.nil? || port.empty?

  env = {
    'REQUEST_METHOD' => req[:method],
    'SCRIPT_NAME' => '',
    'PATH_INFO' => path_info,
    'REQUEST_PATH' => path_info,
    'REQUEST_URI' => req[:raw_path],
    'QUERY_STRING' => req[:query].to_s,
    'SERVER_NAME' => name,
    'SERVER_PORT' => port,
    'SERVER_PROTOCOL' => req[:version],
    'SERVER_SOFTWARE' => 'crucible/rack-sidecar',
    'REMOTE_ADDR' => remote_addr(req),
    'CONTENT_TYPE' => req[:headers]['content-type'].to_s,
    'CONTENT_LENGTH' => req[:body].bytesize.to_s,
    'HTTP_HOST' => host.empty? ? (port == '80' ? name : "#{name}:#{port}") : host,
    'rack.version' => [1, 3],
    'rack.url_scheme' => 'http',
    'rack.input' => StringIO.new(req[:body]),
    'rack.errors' => $stderr,
    'rack.multithread' => true,
    'rack.multiprocess' => false,
    'rack.run_once' => false,
    'rack.hijack?' => false
  }

  req[:headers].each do |k, v|
    next if k == 'content-type' || k == 'content-length'
    next if k.start_with?('x-crucible-env-') || k == 'x-crucible-rack-path'

    ek = k.upcase.tr('-', '_')
    next unless ek.match?(/\A[A-Z0-9_]+\z/)

    env["HTTP_#{ek}"] = v
  end
  env
end

# `x-crucible-env-<key>` → ENV 覆盖（显式 socket 通道；受管 sidecar 走 spawn env）。
def request_env_overrides(headers)
  out = {}
  headers.each do |k, v|
    next unless k.start_with?('x-crucible-env-')

    key = k.sub('x-crucible-env-', '').upcase
    next unless key.match?(/\A[A-Za-z0-9_]+\z/)

    val = percent_decode(v).force_encoding(Encoding::UTF_8)
    out[key] = val unless val.empty?
  end
  out
end

def with_env_overrides(overrides)
  return yield if overrides.empty?

  ENV_LOCK.synchronize do
    saved = {}
    overrides.each_key { |k| saved[k] = ENV[k] }
    begin
      overrides.each { |k, v| ENV[k] = v }
      yield
    ensure
      saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    end
  end
end

def collect_body(body)
  buf = ''.b
  truncated = false
  close_it = body.respond_to?(:close)
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
    body.close if close_it
  end
  [buf, truncated]
end

STATUS_TEXT = {
  100 => 'Continue', 200 => 'OK', 201 => 'Created', 202 => 'Accepted',
  204 => 'No Content', 206 => 'Partial Content',
  301 => 'Moved Permanently', 302 => 'Found', 303 => 'See Other',
  304 => 'Not Modified', 307 => 'Temporary Redirect', 308 => 'Permanent Redirect',
  400 => 'Bad Request', 401 => 'Unauthorized', 403 => 'Forbidden',
  404 => 'Not Found', 405 => 'Method Not Allowed', 408 => 'Request Timeout',
  409 => 'Conflict', 411 => 'Length Required', 413 => 'Content Too Large',
  415 => 'Unsupported Media Type', 422 => 'Unprocessable Content',
  429 => 'Too Many Requests', 431 => 'Request Header Fields Too Large',
  500 => 'Internal Server Error', 501 => 'Not Implemented', 502 => 'Bad Gateway',
  503 => 'Service Unavailable', 504 => 'Gateway Timeout'
}.freeze

def reason_phrase(code)
  STATUS_TEXT[code] || (code >= 500 ? 'Server Error' : code >= 400 ? 'Client Error' : 'OK')
end

def scrub_paths(text)
  s = text.to_s
  root = DOCROOT
  s = s.gsub("#{root}#{File::SEPARATOR}", '')
  s = s.gsub(root, '.')
  # 其它绝对路径（异常消息里常见的 /usr/lib/ruby/... 栈帧）→ 只保留文件名。
  s.gsub(%r{(?<![\w.])/(?:[^\s:/]+/)+([^\s:]+)}, '\1')
end

# 应用异常：日志完整细节，客户端只拿错误 id + 脱敏摘要。
def app_error_response(script, err, note = nil)
  err_id = format('%08x', (Time.now.to_f * 1_000_000).to_i & 0xffffffff)
  bt = Array(err.backtrace).first(12)
  log("error id=#{err_id} script=#{script}: #{err.class}: #{err.message}")
  bt.each { |line| log("  #{line}") }
  log("  note: #{note}") if note
  summary = scrub_paths("#{err.class}: #{err.message}").gsub(/\s+/, ' ').strip
  summary = summary[0, 400] if summary.length > 400
  body = "500 Internal Server Error (rack sidecar; id=#{err_id}): #{summary}\n"
  [500, [['Content-Type', 'text/plain; charset=utf-8'], ['X-Crucible-Error-Id', err_id]], body, false]
end

def invoke_app(script, req, path_info)
  # `.rb` 是 CGI 兼容脚本（stdin=body + 捕获 stdout + 头块）；Rack 应用只认
  # `.ru`（config.ru/index.ru），避免“为判断是不是 Rack 而把脚本执行两次”。
  if script.end_with?('.rb')
    begin
      status, headers, body = run_cgi_script(script, req, path_info)
      return [status, headers, body, false]
    rescue Exception => e # rubocop:disable Lint/RescueException
      return app_error_response(script, e)
    end
  end

  env = build_rack_env(req, path_info)
  overrides = request_env_overrides(req[:headers])

  begin
    app = app_for(script)
  rescue Exception => e # rubocop:disable Lint/RescueException
    return app_error_response(script, e)
  end

  begin
    result = with_env_overrides(overrides) { app.call(env) }
  rescue Exception => e # rubocop:disable Lint/RescueException
    return app_error_response(script, e)
  end

  result = result.to_a if !result.is_a?(Array) && result.respond_to?(:to_a)
  unless result.is_a?(Array) && result.size >= 3
    return app_error_response(script, RuntimeError.new("应用返回 #{result.class}（需要 [status, headers, body]）"))
  end

  status, headers, body = result[0], result[1], result[2]
  unless status.is_a?(Integer) && status.between?(100, 599)
    return app_error_response(script, RuntimeError.new("status 非法（#{status.inspect}）"))
  end
  unless headers.respond_to?(:each)
    return app_error_response(script, RuntimeError.new("headers 非法（#{headers.class}）"))
  end

  out = ''.b
  truncated = false
  begin
    out, truncated = collect_body(body)
  rescue Exception => e # rubocop:disable Lint/RescueException
    return app_error_response(script, e)
  end
  note = truncated ? "响应体超过 #{MAX_BODY} 字节上限，已截断（script=#{script}）" : nil
  log("truncated socket=#{SOCK} #{note}") if note
  [status, headers, out, truncated]
end

def handle(req)
  decoded = request_path(req)
  raise HttpError.new(400, 'invalid path') if decoded.include?("\0")
  raise HttpError.new(400, 'path traversal rejected') if decoded.split('/').include?('..')

  decoded = '/' if decoded.empty?
  decoded.force_encoding(Encoding::UTF_8)
  raise HttpError.new(400, 'path is not valid UTF-8') unless decoded.valid_encoding?

  script = resolve_app_file(decoded)
  raise HttpError.new(404, "no rack app for #{decoded}") if script.nil?

  invoke_app(script, req, decoded)
end

def response_headers(status, headers, body_len, keep_alive, truncated, head_request)
  out = +"HTTP/1.1 #{status} #{reason_phrase(status)}\r\n"
  env_headers = []
  headers.each do |k, v|
    name = k.to_s
    next if name.empty? || name.match?(/[\r\n\0]/)

    case name.downcase
    when 'content-length', 'transfer-encoding', 'connection', 'keep-alive',
         'status'
      next
    end
    Array(v).each do |one|
      s = one.to_s
      next if s.match?(/[\r\n\0]/)

      env_headers << "#{name}: #{s}\r\n"
    end
  end
  out << env_headers.join
  # RFC 9110 §8.6：1xx/204 响应不得带 Content-Length（304 允许携带实体长度）。
  unless status == 204 || (status >= 100 && status < 200)
    out << "Content-Length: #{body_len}\r\n"
  end
  out << "X-Crucible-Truncated: 1\r\n" if truncated
  out << "Connection: #{keep_alive ? 'keep-alive' : 'close'}\r\n"
  out << "X-Crucible-Engine: rack-sidecar\r\n"
  # HEAD：头（含 Content-Length）照发，body 不写。
  out << "\r\n"
  [out, head_request]
end

def write_response(io, status, headers, body, keep_alive, truncated, head_request)
  head, skip_body = response_headers(status, headers || [], body.bytesize, keep_alive, truncated, head_request)
  io.write(head)
  io.write(body) unless skip_body || body.empty? || status == 204 || status == 304
  io.flush
end

def write_error(io, status, message)
  body = "#{status} #{reason_phrase(status)}: #{message}\n"
  io.write("HTTP/1.1 #{status} #{reason_phrase(status)}\r\n" \
           "Content-Type: text/plain; charset=utf-8\r\n" \
           "Content-Length: #{body.bytesize}\r\n" \
           "Connection: close\r\n" \
           "X-Crucible-Engine: rack-sidecar\r\n\r\n#{body}")
  io.flush
rescue IOError, SystemCallError
  nil
end

def serve(io)
  begin
    io.timeout = IO_TIMEOUT if io.respond_to?(:timeout=) && IO_TIMEOUT.positive?
  rescue StandardError
    nil
  end

  loop do
    req = begin
      read_request(io)
    rescue HttpError => e
      write_error(io, e.status, e.message)
      break
    rescue IOError, SystemCallError => e
      log("read: #{e.class}: #{e.message}")
      break
    end
    break if req.nil?

    keep = req[:keep_alive]
    status, headers, body, truncated = begin
      handle(req)
    rescue HttpError => e
      keep = false
      [e.status, [['Content-Type', 'text/plain; charset=utf-8']], "#{e.message}\n", false]
    rescue Exception => e # rubocop:disable Lint/RescueException
      keep = false
      app_error_response('(dispatch)', e)
    end

    head_request = req[:method] == 'HEAD'
    begin
      write_response(io, status, headers, body, keep, truncated, head_request)
    rescue IOError, SystemCallError => e
      log("write: #{e.class}: #{e.message}")
      keep = false
    end
    break unless keep
  end
rescue IOError, SystemCallError => e
  log("conn: #{e.class}: #{e.message}")
ensure
  begin
    io.close
  rescue StandardError
    nil
  end
end

Dir.mkdir(File.dirname(SOCK)) rescue nil
File.unlink(SOCK) rescue nil
server = UNIXServer.new(SOCK)
File.chmod(0o666, SOCK) rescue nil
log("listening on #{SOCK} docroot=#{DOCROOT} prefixes=#{PREFIXES.inspect} " \
    "rack_gem=#{HAVE_RACK_GEM} index=#{DEFAULT_INDEXES.inspect}")

loop do
  conn = server.accept
  Thread.new(conn) { |c| serve(c) }
end
