package com.crucible.jsp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;

import org.apache.jasper.servlet.JspServlet;
import org.eclipse.jetty.apache.jsp.JettyJasperInitializer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.unixdomain.server.UnixDomainServerConnector;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.webapp.WebAppContext;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Jetty Embedded + Jasper JSP sidecar serving HTTP/1.1 over a Unix Domain Socket.
 */
public final class JspSidecarMain {
    static final String ENGINE = "jsp-jetty";

    public static void main(String[] args) throws Exception {
        String sock = System.getenv().getOrDefault("JSP_SOCKET", "state/jsp/jsp.sock");
        String doc = System.getenv().getOrDefault("JSP_DOCROOT", "www-apps/jsp");
        for (int i = 0; i < args.length; i++) {
            if ("--socket".equals(args[i]) && i + 1 < args.length) {
                sock = args[++i];
            } else if ("--docroot".equals(args[i]) && i + 1 < args.length) {
                doc = args[++i];
            }
        }

        Path sockPath = Path.of(sock).toAbsolutePath().normalize();
        if (sockPath.getParent() != null) {
            Files.createDirectories(sockPath.getParent());
        }
        Files.deleteIfExists(sockPath);

        Path docroot = Path.of(doc).toAbsolutePath().normalize();
        if (!Files.isDirectory(docroot)) {
            System.err.println("jsp-jetty: docroot missing: " + docroot);
            System.exit(2);
        }

        Path scratch = Files.createTempDirectory("jsp-sidecar-work-");
        scratch.toFile().deleteOnExit();

        Server server = new Server();

        UnixDomainServerConnector connector = new UnixDomainServerConnector(server);
        connector.setUnixDomainPath(sockPath);
        connector.setIdleTimeout(60_000);
        server.addConnector(connector);

        WebAppContext webapp = new WebAppContext();
        webapp.setContextPath("/");
        webapp.setBaseResource(Resource.newResource(docroot.toUri()));
        webapp.setTempDirectory(scratch.toFile());
        webapp.setParentLoaderPriority(true);
        webapp.setExtractWAR(false);
        webapp.setCopyWebDir(false);
        webapp.setCopyWebInf(false);

        // Allow Jasper to see JSP API jars inside the shaded classpath.
        webapp.setAttribute(
                "org.eclipse.jetty.server.webapp.ContainerIncludeJarPattern",
                ".*/.*jsp-api-[^/]*\\.jar$|.*/.*jasper[^/]*\\.jar$|.*/.*taglibs[^/]*\\.jar$|.*/jsp-sidecar[^/]*\\.jar$");

        // Initialize Jasper (apache-jsp).
        webapp.addServletContainerInitializer(new JettyJasperInitializer());
        webapp.setAttribute("org.apache.catalina.jsp_classpath", System.getProperty("java.class.path"));

        ServletHolder jsp = new ServletHolder("jsp", JspServlet.class);
        jsp.setInitParameter("fork", "false");
        jsp.setInitParameter("xpoweredBy", "false");
        jsp.setInitParameter("development", "true");
        jsp.setInitParameter("compilerTargetVM", "17");
        jsp.setInitParameter("compilerSourceVM", "17");
        jsp.setInitParameter("keepgenerated", "true");
        jsp.setInitParameter("scratchdir", scratch.resolve("jsp").toString());
        jsp.setInitOrder(1);
        webapp.addServlet(jsp, "*.jsp");
        webapp.addServlet(jsp, "*.jspx");

        ServletHolder action = new ServletHolder("actionBridge", new ActionBridgeServlet(docroot));
        action.setInitOrder(2);
        webapp.addServlet(action, "*.do");
        webapp.addServlet(action, "*.action");

        ServletHolder def = new ServletHolder("default", DefaultServlet.class);
        def.setInitParameter("dirAllowed", "false");
        def.setInitParameter("welcomeServlets", "true");
        def.setInitOrder(10);
        webapp.addServlet(def, "/");

        FilterHolder engine = new FilterHolder(new EngineHeaderFilter());
        webapp.addFilter(engine, "/*", EnumSet.of(
                DispatcherType.REQUEST, DispatcherType.FORWARD,
                DispatcherType.INCLUDE, DispatcherType.ERROR));

        server.setHandler(webapp);
        server.start();
        System.err.println("jsp-jetty sidecar on " + sockPath + " docroot=" + docroot);
        server.join();
    }

    /** Adds X-Crucible-Engine: jsp-jetty on every response. */
    static final class EngineHeaderFilter implements Filter {
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            if (response instanceof HttpServletResponse http) {
                http.setHeader("X-Crucible-Engine", ENGINE);
            }
            chain.doFilter(request, response);
        }
    }

    /**
     * Bridges *.do / *.action to a sibling *.jsp when present;
     * otherwise returns a clear 200 stub with the engine header.
     */
    static final class ActionBridgeServlet extends HttpServlet {
        private final Path docroot;

        ActionBridgeServlet(Path docroot) {
            this.docroot = docroot;
        }

        @Override
        protected void service(HttpServletRequest req, HttpServletResponse resp)
                throws ServletException, IOException {
            resp.setHeader("X-Crucible-Engine", ENGINE);
            String uri = req.getRequestURI();
            if (uri == null || uri.isEmpty()) {
                uri = "/";
            }
            String jspUri = uri.replaceAll("\\.(do|action)$", ".jsp");
            String rel = jspUri.startsWith("/") ? jspUri.substring(1) : jspUri;
            Path candidate = docroot.resolve(rel).normalize();
            if (candidate.startsWith(docroot) && Files.isRegularFile(candidate)) {
                req.getRequestDispatcher(jspUri).forward(req, resp);
                return;
            }
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.setContentType("text/plain; charset=utf-8");
            resp.getWriter().write("action bridge stub path=" + uri + "\n");
        }
    }

    private JspSidecarMain() {}
}
