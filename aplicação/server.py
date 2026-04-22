"""
server.py — Servidor HTTP simples para a aplicação TechShop
Usado no GitHub Actions para subir a app localmente antes do scan ZAP.

⚠️  Este servidor é propositalmente inseguro para fins didáticos:
    - Sem HTTPS
    - Sem headers de segurança (CSP, X-Frame-Options, etc.)
    - Sem rate limiting
"""

import http.server
import socketserver
import os
import sys
import urllib.parse

PORT = int(os.environ.get("PORT", 8080))
DIRECTORY = os.path.dirname(os.path.abspath(__file__))


class VulnerableHandler(http.server.SimpleHTTPRequestHandler):
    """
    Handler HTTP vulnerável — propositalmente sem:
      - Content-Security-Policy
      - X-Frame-Options
      - X-Content-Type-Options
      - Strict-Transport-Security
      - Referrer-Policy
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def end_headers(self):
        # ⚠️ VULNERABILIDADE: headers de segurança ausentes intencionalmente
        # Em produção SEMPRE adicione:
        #   self.send_header("Content-Security-Policy", "default-src 'self'")
        #   self.send_header("X-Frame-Options", "DENY")
        #   self.send_header("X-Content-Type-Options", "nosniff")
        #   self.send_header("Referrer-Policy", "no-referrer")

        # ⚠️ VULNERABILIDADE: CORS aberto para qualquer origem
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

        # ⚠️ Expõe versão do servidor
        self.send_header("Server", "TechShop/1.0 Python/" + sys.version.split()[0])

        super().end_headers()

    def do_GET(self):
        """Processa requisições GET — inclui rota /login vulnerável a SQLi simulado."""
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # ⚠️ Rota /login — recebe user/pass via GET (expõe na URL e logs)
        if parsed.path == "/login":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            # ⚠️ VULNERABILIDADE: loga credenciais em texto puro
            print(f"[LOGIN] user={username!r} pass={password!r}", flush=True)

            # ⚠️ "Consulta SQL" sem prepared statements (simulado)
            # query = f"SELECT * FROM users WHERE user='{username}' AND pass='{password}'"
            # SQLi clássico: admin' OR '1'='1

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

            response = f"""
            <!DOCTYPE html><html><body>
            <h2>Login recebido</h2>
            <!-- ⚠️ Credenciais refletidas na resposta (Information Disclosure) -->
            <p>Usuário: {username}</p>
            <p>Senha: {password}</p>
            <a href="/">Voltar</a>
            </body></html>
            """
            # ⚠️ Reflete entrada do usuário sem sanitização
            self.wfile.write(response.encode("utf-8"))
            return

        # Serve arquivos estáticos normalmente
        super().do_GET()

    def log_message(self, format, *args):
        """Log colorido no terminal."""
        print(f"  \033[90m[HTTP]\033[0m {self.address_string()} — {format % args}",
              flush=True)


def main():
    os.chdir(DIRECTORY)

    print(f"\n  \033[1;31m⚡ TechShop Dev Server\033[0m")
    print(f"  \033[90m{'─'*40}\033[0m")
    print(f"  Servindo: \033[1m{DIRECTORY}\033[0m")
    print(f"  URL:      \033[1;36mhttp://0.0.0.0:{PORT}\033[0m")
    print(f"  \033[33m⚠️  Servidor INSEGURO — apenas para testes ZAP\033[0m")
    print(f"  \033[90m{'─'*40}\033[0m\n")

    with socketserver.TCPServer(("0.0.0.0", PORT), VulnerableHandler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\033[90m  Servidor encerrado.\033[0m\n")


if __name__ == "__main__":
    main()
