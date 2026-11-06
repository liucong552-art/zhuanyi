#!/usr/bin/env python3
"""jieshu two-command VPS handover transport (Python 3 standard library + OpenSSL).

Source VPS:
  curl -fsSL https://raw.githubusercontent.com/liucong552-art/zhuanyi/main/jieshu_transfer.py -o /root/jieshu_transfer.py && chmod 700 /root/jieshu_transfer.py && python3 /root/jieshu_transfer.py send

Copy the single complete command printed by send to the destination VPS.
The helper uses an ephemeral pinned-TLS transfer; node secrets never go to GitHub.
Import is incremental: preserves existing destination nodes, 443, and WireGuard.
"""
import argparse
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

RAW_ROOT = 'https://raw.githubusercontent.com/liucong552-art/zhuanyi/main/'
ENGINE_NAME = 'jieshu_node_migrate_incremental.py'
ENGINE_SHA256 = 'e39bb58fa288a6571ca4bc7fd0584081834d0d9c8c7c67bfd779d8acdbfd46b9'
TRANSFER_NAME = 'jieshu_transfer.py'
MAX_BUNDLE = 100 * 1024 * 1024  # Do not accept arbitrarily large downloads.
DEFAULT_PORT = 48999
DEFAULT_TTL = 1200


def fail(message):
    raise RuntimeError(message)


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for part in iter(lambda: fh.read(1 << 20), b''):
            h.update(part)
    return h.hexdigest()


def ensure_engine():
    """Fetch a fixed, verified version of the previously field-tested importer."""
    dest = Path('/root') / ENGINE_NAME
    if dest.is_file() and digest(dest) == ENGINE_SHA256:
        return dest
    # Do not overwrite another local version until a complete verified download.
    fd, name = tempfile.mkstemp(prefix='.jieshu-engine-', dir='/root')
    try:
        with os.fdopen(fd, 'wb') as out, urlopen(RAW_ROOT + ENGINE_NAME, timeout=25) as inp:
            amount = 0
            while True:
                part = inp.read(65536)
                if not part:
                    break
                amount += len(part)
                if amount > 200000:
                    fail('GitHub 核心脚本大小异常')
                out.write(part)
        if digest(name) != ENGINE_SHA256:
            fail('GitHub 核心脚本 SHA256 不匹配；拒绝运行')
        os.chmod(name, 0o700)
        os.replace(name, dest)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return dest


def public_ipv4(override):
    if override:
        try:
            return str(ipaddress.IPv4Address(override))
        except ValueError:
            fail('参数 --public-ip 必须是 IPv4 地址')
    try:
        with urlopen('https://api.ipify.org', timeout=8) as resp:
            return str(ipaddress.IPv4Address(resp.read(50).decode().strip()))
    except Exception:
        fail('无法自动查询本机公网 IPv4；请在 send 后面增加 --public-ip 你的VPS公网IP')


def create_cert(directory):
    cert, key = directory / 'cert.pem', directory / 'key.pem'
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
        '-days', '1', '-subj', '/CN=jieshu-once-transfer',
        '-keyout', str(key), '-out', str(cert)
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    cert.chmod(0o600)
    der = ssl.PEM_cert_to_DER_cert(cert.read_text(encoding='ascii'))
    return hashlib.sha256(der).hexdigest()


class OneTimeHandler(BaseHTTPRequestHandler):
    """Read-only HTTPS endpoint, with a high entropy one-time path."""
    served = False
    def do_GET(self):
        server = self.server
        if self.path != '/bundle/' + server.token or time.time() > server.deadline or self.served:
            self.send_error(404)
            return
        size = server.bundle.stat().st_size
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(size))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            with server.bundle.open('rb') as fh:
                shutil.copyfileobj(fh, self.wfile, 1 << 18)
            self.__class__.served = True
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            # A partial download does not consume the one-time transfer.
            return

    def log_message(self, *_):
        pass  # Do not put the bearer token into HTTP access logs.


def serve_worker(directory):
    base = Path(directory).resolve()
    cfg = json.loads((base / 'session.json').read_text(encoding='utf-8'))
    OneTimeHandler.served = False
    try:
        server = HTTPServer(('0.0.0.0', cfg['port']), OneTimeHandler)
        server.token = cfg['token']
        server.bundle = base / 'bundle.tar.gz'
        server.deadline = cfg['deadline']
        server.timeout = 1
        server.socket.settimeout(60)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(base / 'cert.pem'), str(base / 'key.pem'))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        (base / 'ready').write_text('ready', encoding='ascii')
        while time.time() < server.deadline and not OneTimeHandler.served:
            server.handle_request()
    finally:
        shutil.rmtree(base, ignore_errors=True)


def send(args):
    if os.geteuid() != 0:
        fail('必须用 root 执行')
    public_ip = public_ipv4(args.public_ip)
    engine = ensure_engine()
    base = Path(tempfile.mkdtemp(prefix='.jieshu-transfer-', dir='/root'))
    base.chmod(0o700)
    worker = None
    try:
        bundle = base / 'bundle.tar.gz'
        print('正在保存源 VPS 配额并导出节点（不会停止源节点）...', flush=True)
        subprocess.run(['python3', str(engine), 'export', str(bundle)], check=True)
        if not bundle.is_file() or bundle.stat().st_size > MAX_BUNDLE:
            fail('迁移包缺失或大小超过 100MiB')
        bundle.chmod(0o600)
        cert_fp = create_cert(base)
        token = secrets.token_urlsafe(36)
        deadline = int(time.time()) + args.ttl
        info = dict(port=args.port, token=token, deadline=deadline)
        (base / 'session.json').write_text(json.dumps(info), encoding='utf-8')
        (base / 'session.json').chmod(0o600)
        log = (base / 'server.log').open('ab')
        try:
            worker = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), '_serve-worker', str(base)],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True,
                close_fds=True)
        finally:
            log.close()
        for _ in range(100):
            if (base / 'ready').exists():
                break
            if worker.poll() is not None:
                fail('临时 HTTPS 服务启动失败；检查端口 {} 是否已经占用'.format(args.port))
            time.sleep(0.1)
        else:
            fail('启动临时 HTTPS 服务超时')
        # Pass the token only inside this SSH terminal, not to any public site.
        cmd = (
            'curl -fsSL ' + shlex.quote(RAW_ROOT + TRANSFER_NAME) +
            ' -o /root/' + TRANSFER_NAME +
            ' && chmod 700 /root/' + TRANSFER_NAME +
            ' && python3 /root/' + TRANSFER_NAME +
            ' receive --from ' + shlex.quote(public_ip) +
            ' --port ' + str(args.port) +
            ' --pin ' + cert_fp +
            ' --token ' + shlex.quote(token) +
            ' --sha256 ' + digest(bundle)
        )
        print('\n✅ 源端已准备好：一次性 HTTPS 传输将在 {} 分钟后自动关闭。'.format(args.ttl // 60))
        print('请在【目标 VPS】粘贴以下完整的一行命令：\n')
        print(cmd)
        print('\n⚠️ 不要把上面的完整命令或 token 发到聊天/公开平台。')
        print('若目标连接超时，检查源 VPS 的 TCP {} 入站防火墙是否放行。'.format(args.port))
        return
    except Exception:
        if worker is not None and worker.poll() is None:
            worker.terminate()
        shutil.rmtree(base, ignore_errors=True)
        raise


def fetch_pinned(host, port, pin, token, expected_sha, destination):
    """Pin certificate BEFORE sending the bearer token, on the SAME TLS socket."""
    try:
        host = str(ipaddress.IPv4Address(host))
    except ValueError:
        fail('--from 必须是源 VPS 的 IPv4 地址')
    if len(pin) != 64 or any(c not in '0123456789abcdef' for c in pin):
        fail('HTTPS 证书指纹无效')
    if len(expected_sha) != 64 or any(c not in '0123456789abcdef' for c in expected_sha):
        fail('迁移包 SHA256 无效')
    if not (20 <= len(token) <= 160 and all(c.isalnum() or c in '-_' for c in token)):
        fail('一次性 token 格式错误')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Replaced with exact certificate pin below.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection(host, port, timeout=25, context=context)
    try:
        connection.connect()
        received_pin = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        if not secrets.compare_digest(received_pin, pin):
            fail('证书指纹不匹配：拒绝发送传输令牌，可能连错源 VPS')
        connection.request('GET', '/bundle/' + token)
        resp = connection.getresponse()
        if resp.status != 200:
            fail('迁移包下载失败：HTTP {}'.format(resp.status))
        length_str = resp.getheader('Content-Length')
        if not length_str or not length_str.isdecimal() or not 0 < int(length_str) <= MAX_BUNDLE:
            fail('迁移包长度无效或超过 100MiB')
        remaining = int(length_str)
        with destination.open('wb') as out:
            while remaining:
                chunk = resp.read(min(262144, remaining))
                if not chunk:
                    fail('迁移包未完整收到')
                out.write(chunk)
                remaining -= len(chunk)
        destination.chmod(0o600)
        if digest(destination) != expected_sha:
            fail('迁移包 SHA256 不匹配；拒绝导入')
    finally:
        connection.close()


def receive(args):
    if os.geteuid() != 0:
        fail('必须用 root 执行')
    engine = ensure_engine()
    with tempfile.TemporaryDirectory(prefix='.jieshu-receive-', dir='/root') as tmp:
        archive = Path(tmp) / 'bundle.tar.gz'
        print('正在通过证书指纹校验的 HTTPS 下载源 VPS 的一次性迁移包...', flush=True)
        fetch_pinned(args.source_ip, args.port, args.pin, args.token, args.sha256, archive)
        print('✅ 校验通过；开始预检查节点、端口、NAT 策略和配置版本...', flush=True)
        subprocess.run(['python3', str(engine), 'import', str(archive), '--check-only'], check=True)
        print('✅ 预检查通过；开始实际增量导入...', flush=True)
        subprocess.run(['python3', str(engine), 'import', str(archive)], check=True)
    print('\n✅ 导入完成。源 VPS 不会被清空。测试普通/NAT 实际连接后，再修改原域名 A 记录。')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='action', required=True)
    src = sub.add_parser('send', help='源 VPS：导出 + 临时 HTTPS 服务，并显示目标端命令')
    src.add_argument('--public-ip', help='指定源 VPS 公网 IPv4（默认自动查询）')
    src.add_argument('--port', type=int, default=DEFAULT_PORT, help='临时 HTTPS 监听 TCP 端口（默认 48999）')
    src.add_argument('--ttl', type=int, default=DEFAULT_TTL, help='传输服务存活秒数（默认 1200）')
    dest = sub.add_parser('receive', help='目标 VPS：下载并自动预检查 + 增量导入')
    dest.add_argument('--from', dest='source_ip', required=True, help='源 VPS 公网 IPv4')
    dest.add_argument('--port', type=int, required=True)
    dest.add_argument('--pin', required=True, help='源临时 HTTPS 证书 SHA256 指纹')
    dest.add_argument('--token', required=True, help='一次性传输 token')
    dest.add_argument('--sha256', required=True, help='迁移包 SHA256')
    worker = sub.add_parser('_serve-worker', help=argparse.SUPPRESS)
    worker.add_argument('directory')
    args = parser.parse_args()
    if args.action in ('send', 'receive') and not 1024 <= args.port <= 65535:
        parser.error('端口必须在 1024-65535')
    if args.action == 'send' and not 60 <= args.ttl <= 3600:
        parser.error('--ttl 必须在 60-3600 秒')
    try:
        if args.action == 'send':
            send(args)
        elif args.action == 'receive':
            receive(args)
        else:
            serve_worker(args.directory)
    except Exception as ex:
        print('❌ 操作失败：{}'.format(ex), file=sys.stderr)
        if args.action == 'receive':
            print('请勿改 DNS；源 VPS 仍保持运行。', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
