import argparse
import http.server
import json


class JSONHeaderReporter(http.server.BaseHTTPRequestHandler):
    """
    A simple HTTP server which simply returns a JSON representation
    of the request headers.
    """
    def do_GET(self):
        self.send_response(http.server.HTTPStatus.OK)
        body = json.dumps(dict(self.headers), indent=4).encode('utf8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET


def run_server(host, port):
    httpd = http.server.HTTPServer((host, port), JSONHeaderReporter)
    print(f'Running on {host}:{port}')
    httpd.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser('python3 server.py')
    parser.add_argument('--host', default='localhost',
                        help='Local interface, default "localhost"')
    parser.add_argument('--port', default='9000',
                        help='Port to listen on, default 9000')
    args = parser.parse_args()
    run_server(args.host, int(args.port))
