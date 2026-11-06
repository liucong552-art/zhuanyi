#!/usr/bin/env python3
"""jieshu IPv4/IPv6 temporary node take-over helper (run as root).

  VPS1: python3 jieshu_node_migrate_incremental.py export /root/jieshu-temp-nodes.tar.gz
  VPS2: python3 jieshu_node_migrate_incremental.py import /root/jieshu-temp-nodes.tar.gz

Copies unexpired temporary nodes, excludes TCP/443 and main/WireGuard setup.
Target MAY contain existing temporary nodes, provided their ports and tags do
not conflict. Imports preserve original URL, UUID, Reality private key, short ID,
expiry and per-port quota/IP settings, adapting WG policy mark/table/priority of
NAT nodes. Only imported ports have their nftables rules initialized.
"""
import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

STATE = Path('/var/lib/vless-reality')
TEMP = STATE / 'temp'
QUOTA = STATE / 'quota'
IPLIMIT = STATE / 'iplimit'
XRAY = Path('/usr/local/etc/xray')
SYSTEMD = Path('/etc/systemd/system')
WG = Path('/etc/wireguard')
LOCKS = Path('/run/vless-reality')
TAG_RE = re.compile(r'^vless-temp-[A-Za-z0-9._-]{1,96}$')
REQUIRED_TOOLS = ['/usr/local/sbin/vless_restore_all.sh',
                  '/usr/local/sbin/vless_temp_sub.sh',
                  '/usr/local/sbin/vless_audit.sh',
                  '/usr/local/sbin/pq_audit.sh',
                  '/usr/local/sbin/vless_run_temp.sh',
                  '/usr/local/bin/xray']
VERSION_FILES = [
    '/usr/local/lib/vless-reality/common.sh',
    '/usr/local/lib/vless-reality/quota-lib.sh',
    '/usr/local/lib/vless-reality/iplimit-lib.sh',
    '/usr/local/sbin/vless_run_temp.sh',
    '/usr/local/sbin/vless_nat_preflight.sh',
]


def fail(msg):
    raise RuntimeError(msg)


def read_env(path):
    data = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if not line or line.lstrip().startswith('#') or '=' not in line:
            continue
        k, val = line.split('=', 1)
        if re.fullmatch('[A-Z][A-Z0-9_]*', k) and k not in data:
            data[k] = val
    return data


def write_env(path, changed):
    # Preserve original ordering and unknown extension fields.
    path = Path(path)
    existing = path.read_text(encoding='utf-8').splitlines(keepends=True)
    out, seen = [], set()
    for line in existing:
        k = line.split('=', 1)[0]
        if k in changed:
            out.append('{}={}\n'.format(k, changed[k]))
            seen.add(k)
        else:
            out.append(line)
    for k, v in changed.items():
        if k not in seen:
            out.append('{}={}\n'.format(k, v))
    path.write_text(''.join(out), encoding='utf-8')


def hfile(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def lock(name):
    LOCKS.mkdir(parents=True, exist_ok=True)
    fd = open(LOCKS / name, 'a+')
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def check_tools():
    for x in REQUIRED_TOOLS:
        if not Path(x).exists():
            fail('缺少脚本或命令：{}；请确保两台 VPS 已安装同版本 jieshu'.format(x))


def to_int(value, label):
    if not re.fullmatch(r'[0-9]+', str(value or '')):
        fail('{} 非整数：{}'.format(label, value))
    return int(value)


def path_for(tag, suffix):
    return TEMP / '{}.{}'.format(tag, suffix)


def list_entries():
    now = int(time.time())
    entries, ports = [], set()
    for meta in sorted(TEMP.glob('vless-temp-*.env')):
        tag = meta.stem
        if not TAG_RE.fullmatch(tag):
            fail('节点 tag 非法：{}'.format(tag))
        data = read_env(meta)
        if data.get('TAG') != tag:
            fail('节点 tag 与元数据不匹配：{}'.format(meta))
        port = to_int(data.get('PORT'), '{} PORT'.format(tag))
        expiry = to_int(data.get('EXPIRE_EPOCH'), '{} EXPIRE_EPOCH'.format(tag))
        if port < 1 or port > 65535:
            fail('节点端口无效：{}'.format(port))
        if port == 443:
            print('跳过 443 临时节点 {}'.format(tag))
            continue
        if expiry <= now:
            print('跳过已过期节点 {}'.format(tag))
            continue
        if port in ports:
            fail('多个节点使用同一个端口：{}'.format(port))
        ports.add(port)
        ipver = data.get('IP_VERSION', '4')
        if ipver not in ('4', '6'):
            fail('IP_VERSION 非法：{}'.format(tag))
        landing = data.get('LANDING', '')
        if landing not in ('', 'nat'):
            fail('未知 LANDING：{}'.format(tag))
        files = [meta, path_for(tag, 'url'), XRAY / (tag + '.json'), SYSTEMD / (tag + '.service')]
        qfile, ifile = QUOTA / '{}.env'.format(port), IPLIMIT / '{}.env'.format(port)
        if data.get('PQ_LIMIT_BYTES'):
            if not qfile.is_file():
                fail('节点 {} 有配额但缺少 {}'.format(tag, qfile))
            q = read_env(qfile)
            if q.get('PORT') != str(port) or q.get('OWNER_KIND') != 'temp' or q.get('OWNER_TAG') != tag:
                fail('配额归属不匹配：{}'.format(qfile))
            if q.get('REBUILD_PENDING') == '1':
                fail('配额正在重建，拒绝导出：{}'.format(qfile))
            orig = to_int(q.get('ORIGINAL_LIMIT_BYTES'), 'ORIGINAL_LIMIT_BYTES')
            used = to_int(q.get('SAVED_USED_BYTES'), 'SAVED_USED_BYTES')
            left = to_int(q.get('LIMIT_BYTES'), 'LIMIT_BYTES')
            if orig <= 0 or used > orig or orig - used != left:
                fail('配额总额/用量/剩余量不一致：{}'.format(qfile))
        if to_int(data.get('IP_LIMIT', '0'), 'IP_LIMIT') > 0:
            if not ifile.is_file():
                fail('节点 {} 有 IP 限制但缺少 {}'.format(tag, ifile))
            ipm = read_env(ifile)
            if ipm.get('PORT') != str(port) or ipm.get('OWNER_TAG') != tag or ipm.get('OWNER_KIND') != 'temp':
                fail('IP 限制归属不匹配：{}'.format(ifile))
        for optional in (qfile, ifile):
            if optional.is_file():
                files.append(optional)
        for p in files:
            if not p.is_file() or p.is_symlink():
                fail('节点 {} 缺少普通文件：{}'.format(tag, p))
        cfg = json.loads((XRAY / (tag + '.json')).read_text(encoding='utf-8'))
        inbound = cfg['inbounds'][0]
        rs = inbound['streamSettings']['realitySettings']
        if int(inbound['port']) != port or inbound['settings']['clients'][0]['id'] != data['UUID'] or data['SHORT_ID'] not in rs['shortIds']:
            fail('配置和元数据身份不匹配：{}'.format(tag))
        if landing == 'nat' and not any(x.get('tag') == 'nat' for x in cfg.get('outbounds', [])):
            fail('NAT 节点缺少 nat 出站：{}'.format(tag))
        entries.append(dict(tag=tag, port=port, expire=expiry,
                            landing=landing or 'direct', ip_version=ipver,
                            files=[str(x).lstrip('/') for x in files]))
    if not entries:
        fail('没有找到未过期的非 443 临时节点')
    return entries


def do_export(output):
    check_tools()
    if os.geteuid():
        fail('必须 root 运行')
    output = Path(output).resolve()
    if output.exists():
        fail('导出文件已存在，拒绝覆盖：{}'.format(output))
    temp_lock = lock('temp.lock')
    try:
        subprocess.run(['/usr/local/sbin/pq_save_state.sh'], check=True)
        quota_lock = lock('portquota.lock')
        ip_lock = lock('iplimit.lock')
        try:
            entries = list_entries()
            paths = sorted({p for e in entries for p in e['files']})
            versions = {p: hfile(p) for p in VERSION_FILES if Path(p).is_file()}
            if len(versions) < 4:
                fail('安装文件不完整，不能确认迁移兼容性')
            manifest = dict(format='jieshu-node-migration-v1', time=int(time.time()),
                            nodes=entries, files={p: hfile('/' + p) for p in paths},
                            versions=versions)
            output.parent.mkdir(parents=True, exist_ok=True)
            fd, tmppath = tempfile.mkstemp(prefix='.jieshu-export-', suffix='.tar.gz', dir=str(output.parent))
            os.close(fd)
            try:
                with tarfile.open(tmppath, 'w:gz') as tf:
                    payload = json.dumps(manifest, ensure_ascii=False, indent=2).encode('utf-8')
                    info = tarfile.TarInfo('manifest.json')
                    info.size, info.mode = len(payload), 0o600
                    tf.addfile(info, io.BytesIO(payload))
                    for p in paths:
                        tf.add('/' + p, arcname=p, recursive=False)
                os.chmod(tmppath, 0o600)
                os.replace(tmppath, output)
            finally:
                if os.path.exists(tmppath):
                    os.unlink(tmppath)
        finally:
            ip_lock.close()
            quota_lock.close()
    finally:
        temp_lock.close()
    print('导出完成：{}，节点数={}，普通={}，NAT={}'.format(
        output, len(entries), sum(e['landing'] == 'direct' for e in entries),
        sum(e['landing'] == 'nat' for e in entries)))
    print('迁移包包含 Reality 私钥和节点凭据；请通过 SSH/SCP 传输，勿外传。')
    if any(e['ip_version'] == '6' for e in entries):
        print('⚠️ 包含 IPv6 入站节点。仅更改 DNS A 记录不能切换 IPv6 节点，还需规划 AAAA 记录。')


def read_package(inputpath, staging):
    with tarfile.open(inputpath, 'r:gz') as tf:
        members = tf.getmembers()
        byname = {}
        for m in members:
            if not m.isfile() or m.name in byname or m.name.startswith('/') or '..' in Path(m.name).parts:
                fail('迁移包有非法或重复成员：{}'.format(m.name))
            byname[m.name] = m
        if 'manifest.json' not in byname:
            fail('缺少 manifest.json')
        manifest = json.loads(tf.extractfile(byname['manifest.json']).read().decode('utf-8'))
        if manifest.get('format') != 'jieshu-node-migration-v1':
            fail('迁移包版本不支持')
        expected = set(manifest['files']) | {'manifest.json'}
        if set(byname) != expected:
            fail('迁移包文件列表不匹配')
        approved = re.compile(r'^(var/lib/vless-reality/(temp/vless-temp-[A-Za-z0-9._-]+\.(env|url)|quota/[0-9]+\.env|iplimit/[0-9]+\.env)|usr/local/etc/xray/vless-temp-[A-Za-z0-9._-]+\.json|etc/systemd/system/vless-temp-[A-Za-z0-9._-]+\.service)$')
        for rel in manifest['files']:
            if not approved.fullmatch(rel):
                fail('迁移包路径不在白名单中：{}'.format(rel))
            dest = staging / rel
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with open(dest, 'wb') as fh:
                shutil.copyfileobj(tf.extractfile(byname[rel]), fh)
            os.chmod(dest, 0o600)
            if hfile(dest) != manifest['files'][rel]:
                fail('迁移包文件 SHA256 校验失败：{}'.format(rel))
    return manifest


def current_listening_ports():
    result = subprocess.run(['ss', '-ltnH'], check=True, text=True, stdout=subprocess.PIPE)
    ports = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            found = re.search(r':(\d+)$', parts[3])
            if found:
                ports.add(int(found.group(1)))
    return ports


def parse_mark(raw):
    raw = raw.lower().strip()
    if not re.fullmatch(r'(0x[0-9a-f]+|[0-9]+)', raw):
        fail('非法 MARK：{}'.format(raw))
    return int(raw, 16 if raw.startswith('0x') else 10)


def existing_temp_ports():
    """Reserve every port claimed by an existing temporary node, active or not."""
    found = {}
    for path in sorted(TEMP.glob('*.env')):
        data = read_env(path)
        port = to_int(data.get('PORT'), '{} PORT'.format(path.name))
        if not 1 <= port <= 65535:
            fail('VPS2 现有临时节点端口异常：{}'.format(path))
        if port in found:
            fail('VPS2 现有节点有重复端口 {}：{} / {}'.format(port, found[port], path))
        found[port] = path.name
    return found


def restore_new_ports_only(entries):
    """Restore imported nftables state without touching other running ports.

    Do not call vless_restore_all.sh here: pq_restore_all and
    iplimit_restore_all would rebuild protection on existing VPS2 nodes,
    resetting live counters and occupied IP sets.
    """
    bash = r'''set -Eeuo pipefail
source /usr/local/lib/vless-reality/common.sh
source /usr/local/lib/vless-reality/quota-lib.sh
source /usr/local/lib/vless-reality/iplimit-lib.sh
vr_ensure_runtime_dirs
for item in "$@"; do
    port="${item%%:*}"
    if [[ -f "$VR_QUOTA_STATE_DIR/$port.env" ]]; then
        vr_pq_restore_one "$VR_QUOTA_STATE_DIR/$port.env"
    fi
done
vr_pq_unlock
for item in "$@"; do
    port="${item%%:*}"
    ip_version="${item##*:}"
    vr_il_apply_family_guard "$port" "$ip_version"
    if [[ -f "$VR_IPLIMIT_STATE_DIR/$port.env" ]]; then
        vr_il_restore_one "$VR_IPLIMIT_STATE_DIR/$port.env"
    fi
done
vr_il_unlock
'''
    args = ['{}:{}'.format(e['port'], e['ip_version']) for e in entries]
    subprocess.run(['bash', '-c', bash, 'restore-new-ports-only', *args], check=True)


def do_import(inputpath, check_only=False):
    check_tools()
    if os.geteuid():
        fail('必须 root 运行')
    if not Path(inputpath).is_file():
        fail('迁移包不存在：{}'.format(inputpath))
    if not Path('/usr/local/sbin/vless_nat_preflight.sh').exists():
        fail('VPS2 缺少 NAT 节点 preflight，请先安装 natjichang.sh')
    with tempfile.TemporaryDirectory(prefix='jieshu-import-', dir='/root') as td:
        staging = Path(td)
        manifest = read_package(inputpath, staging)
        current = int(time.time())
        entries = manifest['nodes']
        if not entries:
            fail('包中没有节点')
        allowed_files = set(manifest['files'])
        ports = set()
        for e in entries:
            tag, port = e['tag'], e['port']
            if not TAG_RE.fullmatch(tag) or type(port) is not int or not 1 <= port <= 65535 or port == 443 or port in ports:
                fail('迁移包节点 tag/端口非法或重复')
            if e['expire'] <= current:
                fail('{} 已到期；请重新导出（源节点仍可清理）'.format(tag))
            ports.add(port)
            required = {
                'var/lib/vless-reality/temp/{}.env'.format(tag),
                'var/lib/vless-reality/temp/{}.url'.format(tag),
                'usr/local/etc/xray/{}.json'.format(tag),
                'etc/systemd/system/{}.service'.format(tag),
            }
            if not required.issubset(set(e['files'])) or not set(e['files']).issubset(allowed_files):
                fail('节点 {} 文件清单不完整'.format(tag))
            meta = read_env(staging / ('var/lib/vless-reality/temp/{}.env'.format(tag)))
            if meta.get('TAG') != tag or int(meta['PORT']) != port or int(meta['EXPIRE_EPOCH']) != e['expire']:
                fail('节点 manifest 与元数据不匹配：{}'.format(tag))
        expected_files = set(p for e in entries for p in e['files'])
        if expected_files != allowed_files:
            fail('包中混有不属于任何节点的文件')
        for p, recorded_sha in manifest['versions'].items():
            if not Path(p).is_file() or hfile(p) != recorded_sha:
                fail('VPS2 与 VPS1 的项目脚本版本不一致：{}。请先对齐 jieshu 版本，勿直接覆盖运行库。'.format(p))
        reserved = existing_temp_ports()
        conflict_meta = sorted(ports & set(reserved))
        if conflict_meta:
            fail('VPS2 已有临时节点占用端口：{}（不会覆盖）'.format(conflict_meta))
        listening = current_listening_ports()
        conflict = sorted(ports & listening)
        if conflict:
            fail('VPS2 端口已被占用：{}'.format(conflict))
        for rel in allowed_files:
            if (Path('/') / rel).exists() or (Path('/') / rel).is_symlink():
                fail('VPS2 上同名文件已存在，拒绝覆盖：/{}'.format(rel))
        # Adapt per-node NAT fwmark and policy tuple only. Keep WG peer, main Xray and published URLs unchanged.
        natcount = 0
        for e in entries:
            if e['landing'] != 'nat':
                continue
            natcount += 1
            tag = e['tag']
            meta_path = staging / ('var/lib/vless-reality/temp/{}.env'.format(tag))
            meta = read_env(meta_path)
            iface = meta.get('WG_IF') or 'wg-nat'
            if not re.fullmatch('[A-Za-z0-9_.-]{1,15}', iface) or iface in ('.', '..'):
                fail('NAT WG_IF 非法：{}'.format(iface))
            wg_env = WG / '{}.env'.format(iface)
            if not wg_env.is_file():
                fail('找不到 VPS2 自己的 WireGuard 策略配置：{}'.format(wg_env))
            settings = read_env(wg_env)
            mark = parse_mark(settings.get('MARK', ''))
            table = to_int(settings.get('TABLE_ID'), 'TABLE_ID')
            priority = to_int(settings.get('RULE_PRIORITY'), 'RULE_PRIORITY')
            if mark < 1 or mark > 4294967295 or table < 1 or priority < 1:
                fail('WireGuard 策略路由参数非法：{}'.format(wg_env))
            write_env(meta_path, {'MARK': str(mark), 'TABLE_ID': str(table), 'RULE_PRIORITY': str(priority)})
            config_path = staging / ('usr/local/etc/xray/{}.json'.format(tag))
            cfg = json.loads(config_path.read_text(encoding='utf-8'))
            nat_outbounds = [x for x in cfg['outbounds'] if x.get('tag') == 'nat']
            if len(nat_outbounds) != 1:
                fail('NAT outbound 不唯一：{}'.format(tag))
            nat_outbounds[0].setdefault('streamSettings', {}).setdefault('sockopt', {})['mark'] = mark
            config_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            os.chmod(config_path, 0o600)
            print('NAT {}: 采用 VPS2 的 {} MARK={} TABLE={} PRIORITY={}'.format(tag, iface, mark, table, priority))
        # Validate all Xray configs before installing any destination files.
        for e in entries:
            cfg = staging / ('usr/local/etc/xray/{}.json'.format(e['tag']))
            subprocess.run(['/usr/local/bin/xray', 'run', '-test', '-config', str(cfg)], check=True,
                           stdout=subprocess.DEVNULL)
        print('预检查通过：{} 个节点；待写入 {} 个状态/配置文件'.format(len(entries), len(allowed_files)))
        print('待迁移端口：{}'.format(', '.join(str(e['port']) for e in entries)))
        print('VPS2 现有节点端口将保留：{}'.format(', '.join(map(str, sorted(reserved))) or '(无)'))
        if any(e['ip_version'] == '6' for e in entries):
            print('⚠️ 检测到 IPv6 节点；仅修改 DNS A 不会使 IPv6 客户端切换，请同时检查 AAAA。')
        if check_only:
            print('✅ 只检查模式完成：没有写入文件、没有重建规则、没有启动/停止节点。')
            return
        held = lock('temp.lock')
        try:
            # Re-check under lock so concurrent node creations cannot overwrite state.
            if (ports & set(existing_temp_ports())) or (ports & current_listening_ports()):
                fail('检查期间 VPS2 端口被占用，拒绝导入')
            for rel in sorted(allowed_files):
                target = Path('/') / rel
                if target.exists() or target.is_symlink():
                    fail('目标文件刚刚出现，拒绝覆盖：{}'.format(target))
            for rel in sorted(allowed_files):
                target = Path('/') / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(staging / rel, target)
                os.chown(target, 0, 0)
                os.chmod(target, 0o644 if str(target).endswith('.service') else 0o600)
        finally:
            held.close()
    print('文件导入完成；只为迁入端口初始化配额/IP 防护，不修改 VPS2 原有端口...')
    restore_new_ports_only(entries)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    for e in entries:
        service = e['tag'] + '.service'
        subprocess.run(['systemctl', 'enable', service], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'start', service], check=True)
    subprocess.run(['/usr/local/sbin/vless_temp_sub.sh'], check=True)
    subprocess.run(['/usr/local/sbin/vless_audit.sh'], check=True)
    subprocess.run(['/usr/local/sbin/pq_audit.sh'], check=True)
    print('增量导入并启动完成：普通 {} 个，NAT {} 个。VPS2 原有节点保持运行；请先测试，再修改 DNS。'.format(
        len(entries) - natcount, natcount))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=['export', 'import'])
    parser.add_argument('archive', help='完整的本地 tar.gz 路径')
    parser.add_argument('--check-only', action='store_true', help='只检查 import，不修改 VPS2；推荐先执行')
    args = parser.parse_args()
    if args.check_only and args.action != 'import':
        parser.error('--check-only 仅支持 import')
    try:
        if args.action == 'export':
            do_export(args.archive)
        else:
            do_import(args.archive, check_only=args.check_only)
    except Exception as ex:
        print('❌ 操作失败：{}'.format(ex), file=sys.stderr)
        print('不要更改 DNS。导入若已写入部分文件，请先检查 VPS2 日志与服务状态；原 VPS1 未被操作。', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
