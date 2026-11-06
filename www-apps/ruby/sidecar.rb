#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Crucible Ruby app engine — 常驻 sidecar（Unix domain socket 上的 HTTP/1.1）。
#
# 定位（wave22 起）：**回落路径**。默认（Linux）是 libapp_ruby.so 的进程内静态
# 嵌入（规格 §7.8，禁 spawn）；构建缺 libruby、显式 CRUCIBLE_ENABLE_RUBY_EMBED=0、
# 或跨 .so MRI 宿主选举落败时，宿主才走这里。OpenBSD + Ruby 3.4 的嵌入 boot 期
# 会崩，该平台仍默认 sidecar。
# 这里是**一次拉起、长期驻留**的子进程：没有 per-request spawn（不是 CGI），
# 崩溃也只是这个 sidecar 退出，由 webserver 重新拉起，不影响主进程。
#
# CGI 变量与嵌入引擎（script_engine.c 的 ruby_exec_job）逐项对齐：
# REQUEST_METHOD/PATH_INFO/QUERY_STRING/CONTENT_TYPE/CONTENT_LENGTH/REMOTE_ADDR/
# SCRIPT_FILENAME/GATEWAY_INTERFACE/SERVER_SOFTWARE + 全部请求头 → HTTP_*。
# 两者只有引擎标签头（x-crucible-engine: ruby vs ruby-sidecar）不同。
#
# 约定（与 native_http sidecar 一致）：
#   WEBSERVER_LISTEN_UNIX  socket 路径
#   DOCUMENT_ROOT          docroot
#   WEBSERVER_APP_PREFIXES 逗号分隔的路由前缀（转发前已由宿主剥掉，这里兜底再剥一次）
#
# 请求 → 执行 docroot 下的 .rb 脚本：CGI 语义 ENV（HTTP_*、REQUEST_METHOD、
# PATH_INFO、QUERY_STRING、CONTENT_TYPE/LENGTH、REMOTE_ADDR），stdin=请求体，
# 捕获 stdout 作为响应体；脚本可用 "Content-Type: ..."/空行/"Status: ..." 头块。

require 'socket'
require 'stringio'
require 'uri'

SOCK = ENV['WEBSERVER_LISTEN_UNIX'] || ARGV[0] || 'state/ruby/app.sock'
DOCROOT = File.expand_path(ENV['DOCUMENT_ROOT'] || ARGV[1] || Dir.pwd)
PREFIXES = (ENV['WEBSERVER_APP_PREFIXES'] || '').split(',').map(&:strip).reject(&:empty?)
DEFAULT_INDEX = ENV['RUBY_INDEX'] || 'index.rb'
MAX_BODY = 32 * 1024 * 1024

def log(msg)
  warn("ruby-sidecar: #{msg}")
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

def resolve_script(rel)
  rel = '/index.rb' if rel.nil? || rel.empty? || rel == '/'
  full = File.expand_path(File.join(DOCROOT, rel))
  return nil unless full == DOCROOT || full.start_with?("#{DOCROOT}/")
  full = File.join(full, DEFAULT_INDEX) if File.directory?(full)
  File.file?(full) ? full : nil
end

def read_line(io)
  line = io.gets
  return nil if line.nil?
  line.chomp("\r\n")
end

def read_request(io)
  line = read_line(io)
  return nil if line.nil? || line.empty?
  method, target, _ver = line.split(' ', 3)
  return nil if method.nil? || target.nil?

  headers = {}
  while (h = read_line(io))
    break if h.empty?
    k, v = h.split(':', 2)
    next if k.nil?
    headers[k.strip.downcase] = v.to_s.strip
  end
  len = headers['content-length'].to_i
  len = 0 if len.negative? || len > MAX_BODY
  body = len.positive? ? io.read(len).to_s : ''
  uri = URI.parse(target) rescue nil
  {
    method: method,
    path: (uri&.path || target.to_s.split('?', 2).first).to_s,
    query: (uri&.query || target.to_s.split('?', 2)[1]).to_s,
    headers: headers,
    body: body,
    keep_alive: (headers['connection'] || '').downcase != 'close'
  }
end

# 在解释器内执行脚本：CGI ENV + 捕获 stdout（不 spawn 子进程）。
def run_script(script, req)
  saved = {}
  %w[REQUEST_METHOD PATH_INFO QUERY_STRING CONTENT_TYPE CONTENT_LENGTH REMOTE_ADDR
     SCRIPT_FILENAME GATEWAY_INTERFACE SERVER_SOFTWARE].each { |k| saved[k] = ENV[k] }
  saved_http = ENV.keys.select { |k| k.start_with?('HTTP_') }.to_h { |k| [k, ENV[k]] }
  saved_http.each_key { |k| ENV.delete(k) }

  ENV['REQUEST_METHOD'] = req[:method]
  ENV['PATH_INFO'] = req[:path]
  ENV['QUERY_STRING'] = req[:query]
  # 与进程内嵌入引擎一致：宿主在代理时写入真实 peer 的 x-forwarded-for
  # （客户端自带的同名头已被宿主剥掉），sidecar 从这里恢复 REMOTE_ADDR。
  xff = req[:headers]['x-forwarded-for'].to_s.split(',').first.to_s.strip
  ENV['REMOTE_ADDR'] = xff.empty? ? (ENV['REMOTE_ADDR'] || '127.0.0.1') : xff
  ENV['SCRIPT_FILENAME'] = script
  ENV['GATEWAY_INTERFACE'] = 'CGI/1.1'
  ENV['SERVER_SOFTWARE'] = 'crucible/ruby'
  ENV['CONTENT_TYPE'] = req[:headers]['content-type'] if req[:headers]['content-type']
  ENV['CONTENT_LENGTH'] = req[:body].bytesize.to_s
  # 普通请求头 → HTTP_*（CGI 语义）。旧实现只转 `http_` 前缀的头，等于把
  # Host/Cookie/Authorization/X-* 全部丢掉 —— 嵌入引擎能看到这些变量，两种形态
  # 的应用行为不一致（真机 A/B：sidecar 的 HTTP_HOST/HTTP_X_TEST 都是 <unset>）。
  req[:headers].each do |k, v|
    next if k == 'content-type' || k == 'content-length'
    next if k.start_with?('x-crucible-env-') # 内部 .env 通道，不作为 CGI 头暴露

    ek = k.upcase.tr('-', '_')
    next unless ek.match?(/\A[A-Z0-9_]+\z/)

    ENV["HTTP_#{ek}"] = v
  end

  out = StringIO.new
  old_stdout = $stdout
  old_stdin = $stdin
  old_prog = $PROGRAM_NAME
  begin
    $stdout = out
    $stdin = StringIO.new(req[:body])
    $PROGRAM_NAME = script
    load script
    [200, out.string]
  rescue SystemExit => e
    [e.status.zero? ? 200 : 500, out.string]
  rescue StandardError, ScriptError => e
    log("#{script}: #{e.class}: #{e.message}")
    [500, "#{e.class}: #{e.message}\n#{Array(e.backtrace).first(5).join("\n")}\n"]
  ensure
    $stdout = old_stdout
    $stdin = old_stdin
    $PROGRAM_NAME = old_prog
    saved.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    saved_http.each { |k, v| ENV[k] = v }
  end
end

# 脚本输出可能是 CGI 头块（Content-Type/Status/... + 空行）；否则整体当正文。
def split_response(default_status, raw)
  head, sep, rest = raw.partition(/\r?\n\r?\n/)
  unless sep.empty?
    status = default_status
    ctype = nil
    head.split(/\r?\n/).each do |line|
      k, v = line.split(':', 2)
      next if v.nil?
      case k.strip.downcase
      when 'status' then status = v.strip.split(' ', 2).first.to_i
      when 'content-type' then ctype = v.strip
      end
    end
    if ctype || head.downcase.include?('status:')
      return [status, ctype || 'text/plain; charset=utf-8', rest]
    end
  end
  [default_status, 'text/plain; charset=utf-8', raw]
end

STATUS_TEXT = { 200 => 'OK', 404 => 'Not Found', 500 => 'Internal Server Error' }.freeze

def serve(io)
  loop do
    req = read_request(io)
    break if req.nil?

    rel = app_relative(req[:path])
    script = resolve_script(rel)
    if script.nil?
      body = "404 Not Found: no ruby script for #{rel}\n"
      io.write("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\n" \
               "Content-Length: #{body.bytesize}\r\nConnection: keep-alive\r\n\r\n#{body}")
    else
      status, raw = run_script(script, req)
      status, ctype, body = split_response(status, raw)
      io.write("HTTP/1.1 #{status} #{STATUS_TEXT.fetch(status, 'OK')}\r\n" \
               "Content-Type: #{ctype}\r\nContent-Length: #{body.bytesize}\r\n" \
               "Connection: keep-alive\r\nX-Crucible-Engine: ruby-sidecar\r\n\r\n#{body}")
    end
    io.flush
    break unless req[:keep_alive]
  end
rescue IOError, SystemCallError => e
  log("conn: #{e.class}: #{e.message}")
ensure
  io.close rescue nil
end

Dir.mkdir(File.dirname(SOCK)) rescue nil
File.unlink(SOCK) rescue nil
server = UNIXServer.new(SOCK)
# 0600：只有属主（引擎用户）和 root（webserver 主进程）能连。此前是 0o666，配合
# 0755 的父目录 ⇒ **同机任何进程**（包括被攻破的其它引擎，它们同为 www）都能绕过
# webserver 直连本应用 socket，把未鉴权的请求直接打进来。webserver 以 root 连接，
# 不受 DAC 限制，所以收紧到 0600 不损失功能。
File.chmod(0o600, SOCK) rescue nil
log("listening on #{SOCK} docroot=#{DOCROOT} prefixes=#{PREFIXES.inspect}")

loop do
  conn = server.accept
  Thread.new(conn) { |c| serve(c) }
end
