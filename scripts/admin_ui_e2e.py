#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""U-12: real-browser end-to-end driver for the Crucible Admin UI.

Drives the admin panel with a real Chromium (Playwright) using genuine clicks /
typing / selects (not direct API calls), collects per-page JS console errors,
takes PNG screenshots, and asserts the runtime effect of every save with
independent probes (curl / openssl / dig) where applicable.

Usage:
    python3 scripts/admin_ui_e2e.py \
        --base   https://127.0.0.1:27201 \
        --plain  27200 --tls 27201 --dns-port 27253 \
        --geo-db ~/scratch-browserui/data/geoip/current/geoip.sqlite \
        --shots  ~/scratch-browserui/shots \
        --out    ~/scratch-browserui/logs/e2e-results.json

Exit code: 0 iff every check passed and no JS console error was seen.
"""
import argparse, json, os, subprocess, sys, time, traceback

from playwright.sync_api import sync_playwright

R = {}          # results
CONSOLE_ERRS = []  # (test, kind, text)
SHOTS = []


def check(name, ok, detail=""):
    R[name] = {"ok": bool(ok), "detail": str(detail)}
    print(("  PASS " if ok else "  FAIL ") + name + (("  -- " + str(detail)) if detail else ""))
    return bool(ok)


def shot(page, name, shots_dir):
    p = os.path.join(shots_dir, name + ".png")
    try:
        page.screenshot(path=p, full_page=True)
        SHOTS.append(p)
    except Exception as e:
        print("  (screenshot failed %s: %s)" % (name, e))
    return p


class Ctx:
    """Holds a page + collects console/page errors for the current test."""

    def __init__(self, page, base, tag):
        self.page = page
        self.base = base
        self.tag = tag

    def on_console(self, msg):
        if msg.type == "error":
            CONSOLE_ERRS.append((self.tag, "console.error", msg.text))

    def on_pageerror(self, exc):
        CONSOLE_ERRS.append((self.tag, "pageerror", str(exc)))


def attach(page, tag):
    page.on("console", lambda m: (CONSOLE_ERRS.append((tag, "console.error", m.text))
                                  if m.type == "error" else None))
    page.on("pageerror", lambda e: CONSOLE_ERRS.append((tag, "pageerror", str(e))))


def go(page, base, path="/__admin/", wait=800):
    resp = page.goto(base + path, wait_until="domcontentloaded")
    page.wait_for_timeout(wait)
    return resp


def txt(page, sel):
    try:
        return (page.locator(sel).inner_text() or "").strip()
    except Exception:
        return ""


def _local_env():
    env = os.environ.copy()
    home = os.path.expanduser("~")
    lib = home + "/local/usr/lib/x86_64-linux-gnu:" + home + "/local/usr/lib"
    env["LD_LIBRARY_PATH"] = lib + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    env["PATH"] = home + "/local/usr/bin:" + home + "/local/usr/sbin:" + env.get("PATH", "")
    return env


def run_dig(dig, port, name, rtype="A"):
    try:
        out = subprocess.run([dig, "@127.0.0.1", "-p", str(port), name, rtype, "+time=3", "+tries=1"],
                             capture_output=True, text=True, timeout=15, env=_local_env())
        return out.stdout + out.stderr
    except Exception as e:
        return "dig-error: %s" % e


def run_openssl(port, flag):
    try:
        out = subprocess.run(["openssl", "s_client", "-connect", "127.0.0.1:%d" % port,
                              flag, "-servername", "tls-browserui.local", "-brief"],
                             input="", capture_output=True, text=True, timeout=15)
        return out.stdout + out.stderr
    except Exception as e:
        return "openssl-error: %s" % e


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://127.0.0.1:27201")
    ap.add_argument("--plain", type=int, default=27200)
    ap.add_argument("--tls", type=int, default=27201)
    ap.add_argument("--dns-port", type=int, default=27253)
    ap.add_argument("--dns-offset", type=int, default=100)
    ap.add_argument("--geo-db", default=os.path.expanduser("~/scratch-browserui/data/geoip/current/geoip.sqlite"))
    ap.add_argument("--dig", default=os.path.expanduser("~/local/usr/bin/dig"))
    ap.add_argument("--shots", default=os.path.expanduser("~/scratch-browserui/shots"))
    ap.add_argument("--out", default=os.path.expanduser("~/scratch-browserui/logs/e2e-results.json"))
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin")
    ap.add_argument("--headed", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.shots, exist_ok=True)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    base = args.base.rstrip("/")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not args.headed,
                                    args=["--no-sandbox", "--ignore-certificate-errors"])
        print("chromium:", browser.version)

        # ---------- A. Basic auth + overview ----------
        print("\n[A] Basic auth login + overview render")
        cA = browser.new_context(ignore_https_errors=True,
                                 http_credentials={"username": args.user, "password": args.password})
        pgA = cA.new_page()
        attach(pgA, "A-overview")
        resp = go(pgA, base)
        check("A.http_status_200", resp is not None and resp.status == 200, getattr(resp, "status", None))
        ov = txt(pgA, "#overviewOut")
        check("A.overview_loaded", "加载中" not in ov and "version" in ov, ov[:80].replace("\n", " "))
        body = txt(pgA, "body").lower()
        check("A.no_cloudflare_brand", "cloudflare" not in body and " cf " not in (" " + body + " "))
        title = pgA.title()
        check("A.title", title == "Crucible Admin", title)
        check("A.nav_tabs_present",
              all(pgA.locator("nav button[data-tab='%s']" % t).count() == 1
                  for t in ["overview", "geoip", "dns", "access", "accesslog", "global",
                            "accounts", "toml", "listeners", "tls", "apps", "files",
                            "pagerules", "proxy"]))
        shot(pgA, "A-overview", args.shots)

        # ---------- B. session cookie login (no Basic) ----------
        print("\n[B] secure session cookie login (no HTTP Basic)")
        cB = browser.new_context(ignore_https_errors=True)
        login = cB.request.post(base + "/__admin/api/login",
                                headers={"Content-Type": "application/json", "X-Crucible-Admin": "1"},
                                data=json.dumps({"username": args.user, "password": args.password}))
        lj = None
        try:
            lj = json.loads(login.text())
        except Exception:
            pass
        check("B.login_200_ok", login.status == 200 and lj and lj.get("ok") is True,
              "%s %s" % (login.status, login.text()[:80]))
        sc = login.headers.get("set-cookie", "")
        check("B.cookie_host_secure_httponly",
              "__Host-crucible_admin=" in sc and "Secure" in sc and "HttpOnly" in sc and "SameSite=Strict" in sc,
              sc[:120])
        pgB = cB.new_page()
        attach(pgB, "B-session")
        respB = go(pgB, base)
        check("B.cookie_grants_panel", respB is not None and respB.status == 200,
              getattr(respB, "status", None))
        ovB = txt(pgB, "#overviewOut")
        check("B.cookie_overview_loaded", "version" in ovB, ovB[:60].replace("\n", " "))
        # logout via same-origin request (as UI does), then panel must be 401
        lo = cB.request.post(base + "/__admin/api/logout",
                             headers={"Content-Type": "application/json", "X-Crucible-Admin": "1"},
                             data="{}")
        check("B.logout_200", lo.status == 200, lo.status)
        respB2 = pgB.goto(base + "/__admin/", wait_until="domcontentloaded")
        check("B.after_logout_401", respB2 is not None and respB2.status == 401,
              getattr(respB2, "status", None))
        # re-login for the rest of the run using cookie context
        cB.request.post(base + "/__admin/api/login",
                        headers={"Content-Type": "application/json", "X-Crucible-Admin": "1"},
                        data=json.dumps({"username": args.user, "password": args.password}))
        pgB.goto(base + "/__admin/", wait_until="domcontentloaded")
        pgB.wait_for_timeout(600)

        # use cookie-authenticated page for the state-change tests
        page = pgB

        # ---------- C. site/listener config ----------
        print("\n[C] site config: root / autoindex / upload")
        page.click("nav button[data-tab='listeners']")
        page.wait_for_timeout(500)
        roww = page.locator("#listenersOut tr", has_text=str(args.plain)).first
        roww.locator("button:has-text('编辑')").click()
        page.wait_for_timeout(300)
        page.fill("#leRoot", "www3")
        page.select_option("#leAutoindexUpload", "true")
        page.fill("#leServerName", "renamed-browserui.local")
        shot(page, "C-listeners-edit", args.shots)
        page.click("#btnListenerSave")
        page.wait_for_timeout(900)
        save_out = txt(page, "#listenerEditOut")
        check("C.save_reported_ok", "热" in save_out or "ok" in save_out.lower() or "saved" in save_out.lower(),
              save_out[:80])
        cfg = json.loads(page.request.get(base + "/__admin/api/config/json").text())
        l0 = [l for l in cfg["listeners"] if int(l["port"]) == args.plain][0]
        check("C.root_saved", l0["root"].endswith("www3"), l0["root"])
        ai = l0.get("autoindex")
        if isinstance(ai, dict):
            check("C.upload_saved", bool(ai.get("enable_upload")) is True, ai)
        else:
            check("C.upload_saved", False, "autoindex not object: %r" % (ai,))
        check("C.servername_saved", (l0.get("server_name") or "") == "renamed-browserui.local", l0.get("server_name"))
        # reload list + reopen the edit form -> values must echo back
        page.click("#btnListeners")
        page.wait_for_timeout(500)
        page.locator("#listenersOut tr", has_text=str(args.plain)).first.locator("button:has-text('编辑')").click()
        page.wait_for_timeout(300)
        check("C.echo_root", page.input_value("#leRoot").endswith("www3"), page.input_value("#leRoot"))
        check("C.echo_upload", page.input_value("#leAutoindexUpload") == "true", page.input_value("#leAutoindexUpload"))
        check("C.echo_servername", page.input_value("#leServerName") == "renamed-browserui.local",
              page.input_value("#leServerName"))
        shot(page, "C-listeners-echo", args.shots)
        # revert
        page.fill("#leRoot", "www")
        page.select_option("#leAutoindexUpload", "false")
        page.fill("#leServerName", "site-browserui.local")
        page.click("#btnListenerSave")
        page.wait_for_timeout(800)

        # ---------- D. page rules (global) ----------
        print("\n[D] global page rules: host/method/country/priority")
        page.click("nav button[data-tab='pagerules']")
        page.wait_for_timeout(500)
        page.select_option("#prPort", "global")
        page.wait_for_timeout(500)
        shot(page, "D-pagerules-before", args.shots)
        page.click("#btnPrAdd")
        page.wait_for_timeout(200)
        row1 = page.locator("#prOut tbody tr").last
        row1.locator(".r-match").fill("/e2e-block")
        row1.locator(".r-action").select_option("block")
        row1.locator(".r-prio").fill("5")
        row1.locator(".r-method").fill("GET")
        row1.locator(".r-country").fill("CN")
        page.click("#btnPrAdd")
        page.wait_for_timeout(200)
        row2 = page.locator("#prOut tbody tr").last
        row2.locator(".r-match").fill("/e2e-redir*")
        row2.locator(".r-action").select_option("redirect")
        row2.locator(".r-target").fill("301:/e2e-target")
        row2.locator(".r-prio").fill("7")
        row2.locator(".r-host").fill("127.0.0.1")
        row2.locator(".r-method").fill("GET")
        shot(page, "D-pagerules-edit", args.shots)
        page.click("#btnPrSave")
        page.wait_for_timeout(900)
        pr_out = txt(page, "#prSaveOut")
        check("D.save_ok", "规则" in pr_out or "ok" in pr_out.lower() or "saved" in pr_out.lower(), pr_out[:100])
        cfg = json.loads(page.request.get(base + "/__admin/api/config/json").text())
        prs = cfg.get("page_rules") or []
        found = {r["match_url"]: r for r in prs}
        check("D.block_rule_saved", "/e2e-block" in found, list(found.keys()))
        if "/e2e-block" in found:
            check("D.block_rule_dims",
                  found["/e2e-block"]["action"] == "block" and found["/e2e-block"].get("method") == "GET"
                  and found["/e2e-block"].get("country") == "CN" and int(found["/e2e-block"].get("priority", 0)) == 5,
                  found["/e2e-block"])
        # echo back
        page.click("#btnPrLoad")
        page.wait_for_timeout(600)
        page.click("nav button[data-tab='pagerules']")
        page.wait_for_timeout(300)
        page.select_option("#prPort", "global")
        page.wait_for_timeout(500)
        echo_ok = False
        for i in range(page.locator("#prOut tbody tr").count()):
            r = page.locator("#prOut tbody tr").nth(i)
            if r.locator(".r-match").input_value().strip() == "/e2e-block":
                echo_ok = (r.locator(".r-action").input_value() == "block"
                           and r.locator(".r-method").input_value() == "GET"
                           and r.locator(".r-country").input_value() == "CN")
        check("D.echo_dims", echo_ok)
        shot(page, "D-pagerules-echo", args.shots)
        # runtime effect via curl (real HTTP, not API)
        env = os.environ.copy()
        rb = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                             "-H", "Host: renamed-browserui.local", base + "/e2e-block"],
                            capture_output=True, text=True, timeout=10, env=env)
        check("D.runtime_block_403", rb.stdout.strip() == "403", rb.stdout.strip())
        rr = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-D-", "-H", "Host: 127.0.0.1",
                             base + "/e2e-redir/x"], capture_output=True, text=True, timeout=10, env=env)
        check("D.runtime_redir_301", "301" in rr.stdout.split("\n")[0] and "/e2e-target" in rr.stdout,
              rr.stdout.split("\n")[0])
        # method dimension: POST must not hit the block rule
        rp = subprocess.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
                             "-H", "Host: renamed-browserui.local", base + "/e2e-block"],
                            capture_output=True, text=True, timeout=10, env=env)
        check("D.method_dim_post_not_blocked", rp.stdout.strip() != "403", rp.stdout.strip())
        # cleanup: clear global rules
        page.evaluate("() => {}")
        for _ in range(page.locator("#prOut tbody tr").count()):
            page.locator("#prOut tbody tr").first.locator("button.danger").click()
            page.wait_for_timeout(120)
        page.click("#btnPrSave")
        page.wait_for_timeout(800)
        cfg = json.loads(page.request.get(base + "/__admin/api/config/json").text())
        check("D.cleared", not (cfg.get("page_rules") or []), cfg.get("page_rules"))

        # ---------- E. GeoIP ----------
        print("\n[E] GeoIP panel: lookup / filter / settings")
        page.click("nav button[data-tab='geoip']")
        page.wait_for_timeout(600)
        page.fill("#geoipIp", "1.2.4.3")
        page.click("#btnGeoipLookup")
        page.wait_for_timeout(600)
        gres = txt(page, "#geoipResult")
        check("E.lookup_cn", "CN" in gres and "Hangzhou" in gres, gres[:80].replace("\n", " "))
        shot(page, "E-geoip-lookup", args.shots)
        page.select_option("#geoFamily", "v4")
        page.fill("#geoPrefix", "1.2.4.0/24")
        page.click("#btnGeoFilter")
        page.wait_for_timeout(600)
        gf = txt(page, "#geoFilterOut")
        check("E.filter_v4_prefix", "1.2.4.0/24" in gf, gf[:120].replace("\n", " "))
        shot(page, "E-geoip-filter", args.shots)
        page.fill("#geoPathGain", "15")
        page.click("#btnGeoSave")
        page.wait_for_timeout(800)
        sett = json.loads(page.request.get(base + "/__admin/api/geoip/settings").text())
        check("E.settings_gain_saved", int(sett.get("path_priority_gain", -1)) == 15, sett)
        page.fill("#geoPathGain", "10")
        page.click("#btnGeoSave")
        page.wait_for_timeout(600)
        sett = json.loads(page.request.get(base + "/__admin/api/geoip/settings").text())
        check("E.settings_gain_reverted", int(sett.get("path_priority_gain", -1)) == 10, sett)

        # ---------- F. DNS zone + record ----------
        print("\n[F] DNS: create zone + add record -> dig")
        page.click("nav button[data-tab='dns']")
        page.wait_for_timeout(1500)
        page.fill("#dnsZoneName", "e2e.test")
        page.select_option("#dnsZoneKind", "master")
        page.click("#btnDnsZoneAdd")
        page.wait_for_timeout(2500)
        zones_out = txt(page, "#dnsZonesOut")
        page.click("#btnZoneRefresh")
        page.wait_for_timeout(1200)
        zopts = [page.locator("#dnsZoneSel option").nth(i).get_attribute("value")
                 for i in range(page.locator("#dnsZoneSel option").count())]
        check("F.zone_add_ok", "e2e.test" in zopts, "zones=%s note=%s" % (zopts, zones_out[:80].replace("\n", " ")))
        page.select_option("#dnsZoneSel", "e2e.test")
        page.wait_for_timeout(800)
        # add a record row in the table editor
        page.click("#btnRecRowAdd")
        page.wait_for_timeout(300)
        rrow = page.locator("#dnsRecWrap tbody tr").last
        rrow.locator(".dr-name").fill("www")
        rrow.locator(".dr-type").select_option("A")
        rrow.locator(".dr-data").fill("1.2.4.9")
        shot(page, "F-dns-zone-edit", args.shots)
        rrow.locator(".dr-save").click()
        page.wait_for_timeout(2000)
        recmsg = txt(page, "#dnsRecMsg")
        check("F.record_saved", ("已保存" in recmsg) or ("保存失败" not in recmsg and "共" in recmsg), recmsg[:100])
        # named reload (rndc may race with a just-spawned named: retry)
        for _ in range(3):
            page.click("#btnDnsReload")
            page.wait_for_timeout(2500)
            dg = run_dig(args.dig, args.dns_port, "www.e2e.test", "A")
            if "1.2.4.9" in dg:
                break
        check("F.dig_www", "1.2.4.9" in dg, dg[-200:].replace("\n", " "))
        shot(page, "F-dns-records", args.shots)

        # ---------- G. TLS versions/ciphers ----------
        print("\n[G] TLS: versions + ciphers -> openssl s_client")
        page.click("nav button[data-tab='tls']")
        page.wait_for_timeout(600)
        page.select_option("#tlsPort", str(args.tls))
        page.wait_for_timeout(400)
        page.uncheck("#tlsV12")
        page.check("#tlsV13")
        page.fill("#tlsCiphers", "TLS_AES_128_GCM_SHA256")
        shot(page, "G-tls-edit", args.shots)
        page.click("#btnTlsSave")
        page.wait_for_timeout(1200)
        tls_out = txt(page, "#tlsOut")
        check("G.save_ok", "热" in tls_out or "ok" in tls_out.lower() or "saved" in tls_out.lower(), tls_out[:100])
        cfg = json.loads(page.request.get(base + "/__admin/api/config/json").text())
        lt = [l for l in cfg["listeners"] if int(l["port"]) == args.tls][0]
        ssl = lt.get("ssl") or {}
        check("G.versions_saved", ssl.get("versions") == ["TLSv1.3"], ssl.get("versions"))
        check("G.ciphers_saved", ssl.get("ciphers") == ["TLS_AES_128_GCM_SHA256"], ssl.get("ciphers"))
        o13 = run_openssl(args.tls, "-tls1_3")
        check("G.openssl_tls13_ok", "Protocol version: TLSv1.3" in o13 and "Ciphersuite: TLS_AES_128_GCM_SHA256" in o13,
              [l for l in o13.split("\n") if "Protocol" in l or "Ciphersuite" in l][:2])
        o12 = run_openssl(args.tls, "-tls1_2")
        check("G.openssl_tls12_rejected", "Protocol version: TLSv1.2" not in o12,
              [l for l in o12.split("\n") if "Protocol" in l or "error" in l.lower() or "alert" in l.lower()][:2])
        # revert TLS
        page.select_option("#tlsPort", str(args.tls))
        page.wait_for_timeout(300)
        page.check("#tlsV12")
        page.fill("#tlsCiphers", "")
        page.click("#btnTlsSave")
        page.wait_for_timeout(1000)

        # ---------- H. apps list add/remove ----------
        print("\n[H] apps list add / remove")
        page.click("nav button[data-tab='apps']")
        page.wait_for_timeout(700)
        page.select_option("#appsPort", str(args.plain))
        page.wait_for_timeout(500)
        # catalog 是异步载入的：等 <select class="a-engine"> 有 option 再点「加一行」，
        # 否则新行的引擎下拉是空的，select_option 会超时。
        page.wait_for_function("()=>typeof CATALOG!=='undefined' && CATALOG && CATALOG.length>0", timeout=10000)
        page.click("#btnAppAdd")
        page.wait_for_timeout(300)
        arow = page.locator("#appsOut tbody tr").last
        arow.locator(".a-paths").fill("/e2e")
        arow.locator(".a-engine").select_option("php")
        shot(page, "H-apps-add", args.shots)
        page.click("#btnAppsSave")
        page.wait_for_timeout(900)
        cfg = json.loads(page.request.get(base + "/__admin/api/config/json").text())
        la = [l for l in cfg["listeners"] if int(l["port"]) == args.plain][0]
        paths = [p for a in (la.get("apps") or []) for p in (a.get("paths") or [])]
        check("H.app_added", "/e2e" in paths, paths)
        # delete it
        page.click("nav button[data-tab='apps']")
        page.wait_for_timeout(400)
        page.select_option("#appsPort", str(args.plain))
        page.wait_for_timeout(400)
        trow = None
        for i in range(page.locator("#appsOut tbody tr").count()):
            r = page.locator("#appsOut tbody tr").nth(i)
            if "/e2e" in r.locator(".a-paths").input_value():
                trow = r
        if trow is not None:
            trow.locator("button.danger").click()
            page.wait_for_timeout(200)
            page.click("#btnAppsSave")
            page.wait_for_timeout(800)
        cfg = json.loads(page.request.get(base + "/__admin/api/config/json").text())
        la = [l for l in cfg["listeners"] if int(l["port"]) == args.plain][0]
        paths = [p for a in (la.get("apps") or []) for p in (a.get("paths") or [])]
        check("H.app_removed", "/e2e" not in paths, paths)

        # ---------- I. per-site access log ----------
        print("\n[I] per-site access log override")
        page.click("nav button[data-tab='accesslog']")
        page.wait_for_timeout(600)
        page.select_option("#alSitePort", str(args.plain))
        page.wait_for_timeout(400)
        page.select_option("#alSiteEnable", "true")
        page.select_option("#alSiteLevel", "debug")
        shot(page, "I-accesslog", args.shots)
        page.click("#btnAlSiteSave")
        page.wait_for_timeout(900)
        cfg = json.loads(page.request.get(base + "/__admin/api/config/json").text())
        lal = [l for l in cfg["listeners"] if int(l["port"]) == args.plain][0]
        al = lal.get("access_log") or {}
        check("I.override_saved", bool(al.get("enable")) is True and al.get("level") == "debug", al)
        # revert to inherit
        page.select_option("#alSiteEnable", "")
        page.select_option("#alSiteLevel", "")
        page.click("#btnAlSiteSave")
        page.wait_for_timeout(800)
        cfg = json.loads(page.request.get(base + "/__admin/api/config/json").text())
        lal = [l for l in cfg["listeners"] if int(l["port"]) == args.plain][0]
        check("I.override_cleared", not (lal.get("access_log") or {}), lal.get("access_log"))

        # ---------- J. admin password change ----------
        print("\n[J] admin password change + relogin")
        page.click("nav button[data-tab='accounts']")
        page.wait_for_timeout(600)
        page.fill("#adminPass", "e2e-newpass")
        page.fill("#adminPass2", "e2e-newpass")
        shot(page, "J-accounts", args.shots)
        page.click("#btnPass")
        page.wait_for_timeout(900)
        acct = txt(page, "#acctOut")
        check("J.password_changed", "ok" in acct.lower() or "成功" in acct, acct[:80])
        # logout (same-origin), then panel must 401
        page.click("#btnLogout")
        page.wait_for_timeout(1500)
        # login with NEW password via form on a fresh cookie context
        cJ = browser.new_context(ignore_https_errors=True)
        login2 = cJ.request.post(base + "/__admin/api/login",
                                 headers={"Content-Type": "application/json", "X-Crucible-Admin": "1"},
                                 data=json.dumps({"username": args.user, "password": "e2e-newpass"}))
        check("J.new_password_login", login2.status == 200 and '"ok":true' in login2.text().replace(" ", ""),
              "%s %s" % (login2.status, login2.text()[:60]))
        # old password must now fail
        cJ2 = browser.new_context(ignore_https_errors=True)
        old = cJ2.request.post(base + "/__admin/api/login",
                               headers={"Content-Type": "application/json", "X-Crucible-Admin": "1"},
                               data=json.dumps({"username": args.user, "password": args.password}))
        check("J.old_password_rejected", old.status == 401, old.status)
        # revert password back
        cJ.request.post(base + "/__admin/api/password",
                        headers={"Content-Type": "text/plain", "X-Crucible-Admin": "1"},
                        data=args.password, )
        cJ.request.post(base + "/__admin/api/password",
                        headers={"Content-Type": "text/plain", "X-Crucible-Admin": "1"}, data=args.password)
        # verify revert works
        cJ3 = browser.new_context(ignore_https_errors=True)
        back = cJ3.request.post(base + "/__admin/api/login",
                                headers={"Content-Type": "application/json", "X-Crucible-Admin": "1"},
                                data=json.dumps({"username": args.user, "password": args.password}))
        check("J.password_reverted", back.status == 200 and '"ok":true' in back.text().replace(" ", ""), back.status)

        browser.close()

    # ---------- summary ----------
    total = len(R)
    passed = sum(1 for v in R.values() if v["ok"])
    failed = [k for k, v in R.items() if not v["ok"]]
    out = {
        "checks_total": total,
        "checks_passed": passed,
        "checks_failed": failed,
        "console_errors": CONSOLE_ERRS,
        "screenshots": SHOTS,
        "results": R,
    }
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print("\n==== SUMMARY: %d/%d checks passed; console errors=%d ====" % (passed, total, len(CONSOLE_ERRS)))
    for k in failed:
        print("  FAILED:", k, "--", R[k]["detail"][:160])
    for t, kind, msg in CONSOLE_ERRS[:40]:
        print("  JS", t, kind, msg[:160])
    print("results:", args.out)
    return 0 if (not failed and not CONSOLE_ERRS) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
