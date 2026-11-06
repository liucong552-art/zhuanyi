# jieshu 双 VPS 一次性安全迁移（两条命令）

**针对本项目的临时普通节点和 NAT 临时节点。** 不迁移 443 主节点，不覆盖 WireGuard 配置，也不覆盖目标服务器已有临时节点。

## 第一步：在源 VPS 运行一条命令

以 root 身份执行：

    curl -fsSL 'https://raw.githubusercontent.com/liucong552-art/zhuanyi/main/jieshu_transfer.py' -o /root/jieshu_transfer.py && chmod 700 /root/jieshu_transfer.py && python3 /root/jieshu_transfer.py send

此命令会保存当前流量配额，导出未过期的所有普通/NAT 临时节点，自动产生临时自签名 HTTPS 证书和一次性传输令牌，在 TCP 48999 上监听最多 20 分钟，并在终端打印“目标 VPS 的完整一行命令”。

若需要指定源公网 IP，在命令末尾添加 --public-ip 你的源VPS公网IPv4。若 48999 端口被占用，在末尾添加 --port 48998。

**必要网络条件：** 目标 VPS 必须能连接源 VPS 的 TCP 48999。安全组、UFW 或 nftables 如有入站限制，需临时放通这一端口。脚本不会自动修改防火墙。成功传输后会自动关闭服务并删除临时包与证书私钥。

## 第二步：在目标 VPS 运行一条命令

直接复制第一步输出的完整一行命令，到目标 VPS 终端执行。不再需要通过 Windows SCP 搬运压缩包。

目标端将自动执行 HTTPS 证书 SHA256 指纹校验（校验通过前不会发送 token）、下载包 SHA256 校验、配置版本与端口冲突预检查、NAT WireGuard 标记适配、增量导入、独立初始化迁入端口的配额和 IP 规则、启动节点与审计。

导入成功后先实际测试普通节点、NAT 节点，再更改需要切换的域名 A 记录。源 VPS 不会自动清空，也不会停止运行，能够继续服务旧 DNS 缓存客户端。

## 迁移内容

保留：端口、UUID、Reality 私钥与 Short ID、原始公开域名与 URL、原始到期时间、流量配额与导出时已使用量、IP 数量与粘性时间。NAT 节点自动使用目标 VPS 当前 WireGuard 的 MARK、TABLE_ID、RULE_PRIORITY。

不覆盖：目标现有节点、443 主节点、主 Xray 配置、WireGuard Peer/私钥、项目管理脚本。

IP 限额配置能迁移，但 nftables 内实际占用的 IP 地址集合不能实时迁移。DNS 双机并行期间配额各自计数，无法实时相加。

## 后续轮换

哪台 VPS 当前是生产机，哪台就执行第一步。空闲接管机执行第二步，之后测试并修改 DNS。

如果源 VPS 上的节点公开链接同时使用两个域名（例如 meiguo.example.com 和 helan.example.com），迁走全部节点后必须分别处理两个域名的 A 记录。只切换其中一个域名，不会切换使用另一个域名的链接。443 主节点继续由你单独处理。

下一轮必须重新从生产机导出最新数据，不能复用旧包。目标如果已有同名节点或冲突端口，增量导入会拒绝覆盖；旧机必须先按你自己的运维计划处理掉不再需要的临时节点。

## 安全提醒

源端打印给目标端的完整命令里包含一次性 token。请不要将该命令原样发布到聊天、GitHub Issue 或日志。GitHub 仅存程序源代码，迁移包含 Reality 私钥，只经一次性 TLS 通道在两台 VPS 间传输。

如果导入失败，请勿修改 DNS；查看目标机器相关日志，不能直接反复覆盖文件。源 VPS 保持运行。迁移核心已经在你此前的 22 个节点上验证；新增的 HTTPS 传输机制仅做过本地通信测试，尚未在你的真实 VPS 网络上实测。
