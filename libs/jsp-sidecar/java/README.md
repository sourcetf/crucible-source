# Crucible JSP sidecar (Java / Maven skeleton)

Optional Jetty-oriented fat JAR path. **OpenBSD and default demos use the Python UDS sidecar** (`../jsp_sidecar.py`) which speaks the same HTTP/1.1-over-Unix-socket protocol.

## Build

```bash
cd libs/jsp-sidecar/java
mvn -q -DskipTests package
# → target/jsp-sidecar.jar  (also copy to ../target/jsp-sidecar.jar if desired)
mkdir -p ../target && cp -f target/jsp-sidecar.jar ../target/
```

Requires JDK 17+.

## Run

```bash
export JSP_DOCROOT=/path/to/www-apps/jsp
export JSP_SOCKET=/path/to/state/jsp/jsp.sock
java -jar target/jsp-sidecar.jar --socket "$JSP_SOCKET" --docroot "$JSP_DOCROOT"
```

`JspSidecarMain` implements a minimal UDS HTTP loop + naive `<%= %>` / `out.println` render. Full Jasper compilation can be layered later via the Jetty `apache-jsp` dependency already declared in `pom.xml`.

## `.env` injection (`EnvInjectionFilter`)

The web-server host forwards an app's `.env` to **explicitly configured `apps[].socket`** sidecars
(its own process env is unreachable) as per-request headers: name `x-crucible-env-<key lowercased>`,
value percent-encoded (RFC 3986, UTF-8). `EnvInjectionFilter` (registered in `JspSidecarMain`)
turns them into **request attributes**:

```jsp
<p>db=<%= request.getAttribute("crucible.env.db_password") %></p>
<%
  @SuppressWarnings("unchecked")
  java.util.Map<String,String> env = (java.util.Map<String,String>) request.getAttribute("crucible.env");
%>
```

* attribute key = header name minus the prefix, **lowercased**; `crucible.env` holds an immutable
  `Map<String,String>` with every key of that request;
* client-supplied `x-crucible-env-*` headers are stripped by the host before forwarding, so the
  channel cannot be injected from outside; the filter re-applies its own caps
  (64 keys / 8 KiB per value / 16 KiB total) as defence in depth;
* **`System.setProperty` is deliberately not used**: system properties are JVM-global, so with
  several apps on one Jetty a later request would overwrite an earlier value and it would survive
  the request (cross-request / cross-app bleed);
* managed sidecars (`deps/bin/index`) keep the **spawn env** channel: the app just calls
  `System.getenv("KEY")` — the filter neither replaces nor fakes that channel;
* the Python sidecar (`../jsp_sidecar.py`) implements the identical semantics
  (`extract_env_attributes`), so both sidecars read the same `.env` values the same way.

## Prefer Python on OpenBSD

```bash
../jsp_sidecar.sh state/jsp/test.sock www-apps/jsp
```
