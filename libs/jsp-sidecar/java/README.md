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

## Prefer Python on OpenBSD

```bash
../jsp_sidecar.sh state/jsp/test.sock www-apps/jsp
```
