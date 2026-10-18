# gopkg

`gopkg` 是由 elkpi 维护的高性能、低依赖 Go 通用基础设施工具集，专为网络穿透、高性能网关、安全脱敏与系统底层编程而设计。

## 模块导览

### 1. `net/qos` — 高精度网络质量滑动窗口聚合器
- **导入路径**：`github.com/elkpi/gopkg/net/qos`
- **特性**：
  - 纯 Go 标准库实现，零外部依赖，极低内存分配；
  - 参考 **RFC 6298** 的 EWMA 平滑 RTT 统计（α=0.2 为刻意调参，非 RFC 默认 1/8）；
  - 参考 **RFC 3550** 抖动方差（Mean Deviation Jitter）统计；
  - 基于可配置大小的滑动窗口自动聚合计算实时丢包率（`LossRate`）；
  - 适合用于实时链路健康探测、多路径动态切换（Multi-path steering）与 RPC 节点健康度打分。

### 2. `net/underlay` — Linux 底层 Socket 控制与 Ancillary OOB 发送器
- **导入路径**：`github.com/elkpi/gopkg/net/underlay`
- **特性**：
  - **Linux `SO_MARK` 隔离工厂**：在 TCP/UDP Socket 连接建立或监听时安全绑定指定路由标记（Mark），防止复杂策略路由环境下的环路问题；
  - **逐包 TTL 注入（`SendUDPWithTTL`）**：通过内核辅助控制报文（Ancillary OOB `IP_TTL` / `IPV6_UNICAST_HOPS`）在单一 UDP Socket 上发送指定 TTL 报文，无需全局修改 Socket 属性，完美支撑 NAT 穿透低 TTL 探测；
  - **目的地址安全前缀校验**：防止公网载体流量越权回绕至加密 Overlay 地址段。

### 3. `net/portmapper` — 局域网网关端口映射三件套 (NAT-PMP / PCP / UPnP IGD)
- **导入路径**：`github.com/elkpi/gopkg/net/portmapper`
- **特性**：
  - 纯 Go 原生实现，零外部大包依赖；
  - 完整支持 **NAT-PMP** (RFC 6886)、**PCP** (RFC 6887) 与 **UPnP IGD** (SSDP M-SEARCH + SOAP XML)；
  - 自动探测 Linux 系统缺省网关路由，支持三协议并发梯次探测（单播优先，UPnP 兜底）；
  - 支持后台生命周期自动续期（`AutoRenew`）与退出注销（`Release`）。

### 4. `security/securelog` — 密钥与敏感信息全编码递归脱敏引擎
- **导入路径**：`github.com/elkpi/gopkg/security/securelog`
- **特性**：
  - 纯 Go 标准库实现，零外部依赖；
  - 输入敏感文本或原始密钥字节后，自动派生其所有标准编码形态（原始值、Base64、RawBase64、Hex、JSON 转义、URL Query/Path 转义）；
  - 将所有衍生匹配项统一递归替换为 `[REDACTED]`，从根源杜绝密钥在各层序列化或日志中意外泄露。

## 开源协议

MIT License
