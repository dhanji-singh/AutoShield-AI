"""Local scanner benchmark. Database-error responses are synthetic fixtures."""
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

CSS = '''body{background:#111510;color:#ecf1e8;font:17px system-ui;margin:0;padding:7vw;max-width:980px}h1{font-size:clamp(36px,6vw,70px);letter-spacing:-3px}a{color:#c0f365}nav{display:flex;gap:24px;flex-wrap:wrap}section{border:1px solid #394232;padding:26px;margin:22px 0;border-radius:16px}code{overflow-wrap:anywhere}p{line-height:1.65}small{color:#bcc7b6}'''
HARDENED = [('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"), ('X-Content-Type-Options','nosniff')]

def page(title, content):
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>'+escape(title)+' · AutoShield Lab</title><style>'+CSS+'</style>'
            '<small>AUTOSHIELD / LOCAL BENCHMARK</small><h1>'+escape(title)+'</h1>'+content+
            '<p><a href="/">Lab home</a></p><small>Synthetic fixtures. No production data or actual database exploitation.</small></html>')

def route(path):
    """Pure response builder: status, headers, body bytes."""
    p=urlsplit(path)
    q=parse_qs(p.query,keep_blank_values=True).get('q',[''])[0][:512]
    headers=[('Content-Type','text/html; charset=utf-8'),('Cache-Control','no-store')]
    status=200
    if p.path=='/health':
        return 200,[('Content-Type','text/plain')],b'ok'
    if p.path=='/':
        headers+=HARDENED
        body=page('Follow the evidence.', '''<p>A second lab for testing crawl coverage, observations and false-positive handling. Start the scanner at <code>http://fixture-lab:8090/</code>.</p>
<nav><a href="/reflect?q=hello">Reflection</a><a href="/search?q=apple">Error signature</a><a href="/secure?q=apple">Control page</a><a href="/cookie">Cookie flags</a><a href="/redirect">Scope boundary</a></nav>
<section><h2>What to expect</h2><p>Reflection is inconclusive for XSS. The search fixture returns a synthetic SQLITE_ERROR after a quote, so SQL injection must stay suspected. The control page does not reflect input or produce database errors.</p><p>All pages use local HTTP. HTTPS and HSTS are not tested here.</p></section>
<section><h2>Open your tools</h2><a href="http://localhost:8502" target="_blank" rel="noopener">AutoShield dashboard</a> · <a href="http://localhost:8080" target="_blank" rel="noopener">Juice Shop</a></section>''')
    elif p.path=='/reflect':
        # Escaped reflection deliberately demonstrates why a reflected marker is not proof of XSS.
        body=page('Reflection fixture','<p>Escaped input: <code>'+escape(q)+'</code></p><p>Missing CSP/nosniff are intentional. Input is HTML-escaped; this fixture is not an executable XSS example.</p>')
    elif p.path=='/search':
        if "'" in q:
            status=500
            body=page('Synthetic database error','<p>SQLITE_ERROR: benchmark signature (synthetic; no SQL was executed).</p>')
        else:
            body=page('Product search fixture','<p>One demo product: Apple.</p><p>A quote in q triggers a synthetic database-error response.</p>')
    elif p.path=='/secure':
        headers+=HARDENED
        body=page('Control page','<p>Constant output. Query input is not echoed. CSP and nosniff are present. This page is a control for these specific checks, not a claim of complete security.</p>')
    elif p.path=='/cookie':
        headers+=HARDENED+[('Set-Cookie','lab_demo=fixture-only; Path=/')]
        body=page('Cookie observation','<p>This non-sensitive demonstration cookie intentionally omits Secure, HttpOnly and SameSite.</p>')
    elif p.path=='/redirect':
        return 302,headers+[('Location','http://outside.invalid/')],b'Out-of-scope redirect fixture'
    else:
        status=404;headers+=HARDENED;body=page('Not found','<p>No fixture exists at this path.</p>')
    return status,headers,body.encode('utf-8')

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status,headers,body=route(self.path)
        self.send_response(status)
        for name,value in headers: self.send_header(name,value)
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*args):
        pass

if __name__=='__main__':
    ThreadingHTTPServer(('0.0.0.0',8090),Handler).serve_forever()
