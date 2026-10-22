#!/usr/bin/env python3
"""Exercise the built process and reference PHP adapter using disposable local state."""
import hashlib, http.client, json, os, pathlib, secrets, signal, socket, subprocess, tempfile, time
root=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='aegis-smoke-') as tmp:
    d=pathlib.Path(tmp);spool=d/'spool';spool.mkdir(mode=0o700)
    for name in ['token','storage']:
        path=d/(name+'.key');path.write_text(secrets.token_hex(32));path.chmod(0o600)
    # Obtain a free loopback port. The process owns it only during this test.
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    endpoint=f'http://127.0.0.1:{port}/v1/uploads'
    cfg={'enabled':True,'listen':f'127.0.0.1:{port}','staging_dir':str(spool),'token_key_file':str(d/'token.key'),'storage_key_file':str(d/'storage.key'),'policy':{'request_seconds':1}}
    config=d/'config.json';config.write_text(json.dumps(cfg));config.chmod(0o600)
    proc=subprocess.Popen([str(root/'build/aegis'),'serve','--config',str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    def php(code,*args):
        return subprocess.check_output(['php','-r',code,str(root/'integrations/php/AegisStagingClient.php'),endpoint,str(d/'token.key'),*args],text=True)
    bootstrap='require $argv[1]; $c=new \\StarlitDigital\\Aegis\\AegisStagingClient($argv[2],$argv[3]); '
    try:
        for _ in range(100):
            if proc.poll() is not None:raise RuntimeError(proc.stderr.read())
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1):break
            except OSError:time.sleep(.03)
        else:raise RuntimeError('server did not start')
        ticket=json.loads(php(bootstrap+'echo json_encode($c->issueUpload("demo_actor"));'))
        body=json.dumps({'schema_version':1,'name':'Zoë 東京 🛡️','work_entries':[]},ensure_ascii=False).encode()
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
        conn.request('PUT','/v1/uploads',body,{'Authorization':'Bearer '+ticket['token'],'Content-Type':'application/json'})
        res=conn.getresponse();receipt=json.loads(res.read());assert res.status==201;conn.close()
        assert receipt['sha256']==hashlib.sha256(body).hexdigest()
        print('PASS  PHP issued a user and purpose bound upload grant')
        print('PASS  Aegis streamed Unicode JSON into encrypted staging')
        result=php(bootstrap+'echo $c->consume("demo_actor",$argv[4]);',ticket['id']).encode()
        assert result==body
        print('PASS  PHP consumed the exact bytes with SHA256 verification')
        files=list(spool.glob('aegis-session-*/*.stage'));assert not files
        print('PASS  single use retrieval removed the staged object')
        # A declared body that is never sent must hit the local one second deadline.
        ticket=json.loads(php(bootstrap+'echo json_encode($c->issueUpload("demo_actor"));'))
        with socket.create_connection(('127.0.0.1',port),timeout=3) as slow:
            slow.sendall(('PUT /v1/uploads HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer '+ticket['token']+'\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n').encode())
            started=time.monotonic();response=slow.recv(4096);elapsed=time.monotonic()-started
            assert elapsed<2.5 and (b'400' in response or not response)
        print('PASS  stalled upload terminated by the local timing limit')
        assert not list(spool.glob('aegis-session-*/*.stage'))
    finally:
        proc.send_signal(signal.SIGTERM)
        try:out,err=proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:proc.kill();out,err=proc.communicate();raise RuntimeError('shutdown deadline exceeded')
        if proc.returncode!=0:raise RuntimeError(err)
    assert not list(spool.glob('aegis-session-*'))
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=.2):raise RuntimeError('listener still open')
    except ConnectionRefusedError:pass
    print('PASS  process stopped; listener, temporary keys and staging retired')
