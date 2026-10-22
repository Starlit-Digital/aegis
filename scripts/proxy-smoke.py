#!/usr/bin/env python3
"""Run the built proxy against disposable Unix HTTP and optional PHP FPM backends."""
import http.client
import http.server
import json
import pathlib
import shutil
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

root = pathlib.Path(__file__).resolve().parents[1]

def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait(proc, address, unix=False):
    for _ in range(150):
        if proc.poll() is not None:
            raise RuntimeError('test process exited: ' + proc.communicate()[1])
        try:
            with socket.socket(socket.AF_UNIX if unix else socket.AF_INET) as s:
                s.settimeout(.1)
                s.connect(address)
            return
        except OSError:
            time.sleep(.02)
    raise RuntimeError('test listener did not start')

def stop(proc):
    proc.send_signal(signal.SIGTERM)
    try:
        _, err = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError('shutdown timed out')
    if proc.returncode != 0:
        raise RuntimeError(err)

class Backend(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'body': body.decode(), 'type': self.headers['Content-Type'], 'host': self.headers['Host']}).encode())
    def log_message(self, *_):
        pass

with tempfile.TemporaryDirectory(prefix='aegis-proxy-', dir='/tmp') as tmp:
    d = pathlib.Path(tmp)
    backend = socketserver.UnixStreamServer(str(d/'http.sock'), Backend)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    fpm = None
    protocols = ['http']
    fpm_path = shutil.which('php-fpm')
    if fpm_path:
        (d/'index.php').write_text('''<?php
header('Content-Type: application/json');
echo json_encode(['body'=>file_get_contents('php://input'), 'post'=>$_POST,
 'type'=>$_SERVER['CONTENT_TYPE'] ?? '', 'host'=>$_SERVER['HTTP_HOST'],
 'script'=>$_SERVER['SCRIPT_FILENAME'], 'https'=>$_SERVER['HTTPS'] ?? '',
 'override'=>$_SERVER['PHP_VALUE'] ?? null]);
''')
        (d/'fpm.conf').write_text(f'''[global]
error_log = {d}/fpm.log
daemonize = no
[isolated]
listen = {d}/php.sock
pm = static
pm.max_children = 1
catch_workers_output = yes
php_admin_value[session.upload_progress.enabled] = 0
''')
        fpm = subprocess.Popen([fpm_path, '-n', '-F', '-y', str(d/'fpm.conf')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            wait(fpm, str(d/'php.sock'), True)
            protocols.append('fastcgi')
        except BaseException:
            if fpm.poll() is None:
                stop(fpm)
            backend.shutdown()
            backend.server_close()
            raise
    try:
        for protocol in protocols:
            listen, admin = port(), port()
            key = '07'*32
            (d/'admin.key').write_text(key)
            (d/'admin.key').chmod(0o600)
            route = {'prefix': '/api', 'protocol': protocol, 'socket': str(d/('http.sock' if protocol=='http' else 'php.sock')), 'server_name': 'app.test', 'methods': ['POST'], 'formats': ['json', 'form', 'multipart']}
            if protocol == 'fastcgi':
                route.update(script_filename=str(d/'index.php'), document_root=str(d), script_name='/index.php', server_port=443, https=True)
            config = {'enabled': True, 'mode': 'proxy', 'listen': f'127.0.0.1:{listen}', 'admin_listen': f'127.0.0.1:{admin}', 'admin_key_file': str(d/'admin.key'), 'proxy': {'hosts': ['app.test'], 'routes': [route], 'request_seconds': 1}}
            (d/'config.json').write_text(json.dumps(config))
            proc = subprocess.Popen([str(root/'build/aegis'), 'serve', '--config', str(d/'config.json')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            def call(path, body, ct='application/json', extra=None):
                conn = http.client.HTTPConnection('127.0.0.1', listen, timeout=3)
                headers = {'Host': 'app.test', 'Content-Type': ct}
                headers.update(extra or {})
                conn.request('POST', path, body.encode(), headers)
                response = conn.getresponse()
                data = response.read()
                conn.close()
                return response.status, data
            try:
                wait(proc, ('127.0.0.1', listen))
                status, body = call('/api/profile', '{ "z": "雪", "a": 9007199254740993 }')
                assert status == 200, (status, body)
                result = json.loads(body)
                assert result['body'] == '{"a":9007199254740993,"z":"雪"}' and result['host']=='app.test', result
                if protocol == 'fastcgi':
                    assert result['script']==str(d/'index.php') and result['https']=='on' and result['override'] is None
                print(f'PASS  {protocol}: Unicode JSON rebuilt, numbers preserved, fixed local backend')
                status, body = call('/api/profile', 'display_name=%E9%9B%AA', 'application/x-www-form-urlencoded')
                assert status==200, (status, body)
                if protocol=='fastcgi':
                    assert json.loads(body)['post']=={'display_name':'雪'}
                    print('PASS  real PHP FPM parsed the rebuilt form and fixed CGI environment')
                assert call('/api/profile', '{"x":1,"x":2}')[0]==400
                assert call('/api/profile', '{}', extra={'PHP_VALUE': 'auto_prepend_file=/tmp/no'})[0]==400
                assert call('/apievil', '{}')[0]==404
                assert call('/metrics', '{}')[0]==404
                print(f'PASS  {protocol}: duplicate keys, PHP override, prefix confusion and public metrics blocked')
                conn = http.client.HTTPConnection('127.0.0.1', admin, timeout=3)
                conn.request('GET', '/metrics', headers={'Authorization':'Bearer '+key})
                response=conn.getresponse()
                assert response.status==200 and b'aegis_proxy_forwarded_total 2' in response.read()
                conn.close()
                with socket.create_connection(('127.0.0.1', listen), timeout=3) as slow:
                    slow.sendall(b'POST /api HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n')
                    started=time.monotonic()
                    response=slow.recv(4096)
                    assert time.monotonic()-started<2.5 and (not response or b'400' in response)
                print(f'PASS  {protocol}: private metrics and stalled request deadline')
            finally:
                stop(proc)
            for closed in [listen, admin]:
                try:
                    with socket.create_connection(('127.0.0.1', closed), timeout=.1):
                        raise RuntimeError('listener survived shutdown')
                except ConnectionRefusedError:
                    pass
        if not fpm_path:
            print('SKIP  real PHP FPM, php-fpm not on PATH; FastCGI wire tests run in make verify')
    finally:
        backend.shutdown()
        backend.server_close()
        if fpm:
            stop(fpm)
print('PASS  all test processes stopped; temporary config, keys, sockets and PHP fixture removed')
