# pagecache-guard

**[English](README.md)**

一个运行时完整性守护工具，在执行时检测并拦截 Linux 页缓存篡改攻击。

通过 `fanotify` 拦截 SUID/SGID 二进制文件的 `execve()` 调用，使用 `O_DIRECT` 比对页缓存内容与磁盘内容。若不一致则拒绝执行，阻止通过篡改 SUID 文件实现的提权攻击。

## 背景

页缓存覆写类漏洞允许攻击者篡改**只读**文件的内存缓存内容：

| CVE | 名称 | 年份 | O_DIRECT 可检测 |
|-----|------|------|:---------------:|
| CVE-2026-43284 / CVE-2026-43500 | Dirty Frag | 2026 | ✅ |
| CVE-2026-31431 | Copy Fail | 2026 | ✅ |
| CVE-2022-0847 | Dirty Pipe | 2022 | ✅ |
| CVE-2016-5195 | Dirty COW | 2016 | ❌ |

传统安全工具（文件完整性监控、镜像扫描、fs-verity）通过页缓存读取文件，**无法检测**此类攻击。`O_DIRECT` 绕过页缓存直接从磁盘读取，是检测仅修改页缓存的漏洞（Copy Fail、Dirty Pipe、Dirty Frag）的唯一可靠方式。Dirty COW 例外——它会通过 page writeback 将篡改数据写回磁盘，`O_DIRECT` 读到的也是篡改后的内容，需要依赖传统文件完整性工具（AIDE / `rpm -V` / Tripwire）检测。

## 工作原理

```mermaid
flowchart TD
    A[启动 Guard] --> B[扫描目录下所有\nSUID/SGID 文件]
    B --> C[注册 fanotify\n执行权限监控]
    C --> D{二进制被\nexecve}

    D --> E{在 SUID/SGID\n列表中?}
    E -- 否 --> F[FAN_ALLOW\n直接放行]
    E -- 是 --> G{执行者\nUID = 0?}

    G -- 是 --> H[跳过检查\nFAN_ALLOW\nroot 无需提权]
    G -- 否 --> I[O_DIRECT 读磁盘\nvs\nread 读页缓存]

    I --> J{内容\n一致?}
    J -- 是 --> K[FAN_ALLOW\n放行执行]
    J -- 否 --> L[FAN_DENY\n拦截执行\n输出告警]

    F --> D
    H --> D
    K --> D
    L --> D
```

## 快速开始

```bash
# 基本用法 — 监控 /usr /bin /sbin 下的 SUID/SGID 文件
sudo python3 pagecache_guard.py

# 指定监控路径
sudo python3 pagecache_guard.py /usr /bin /sbin

# Dry-run 模式（只告警不拦截）
sudo python3 pagecache_guard.py --dry-run /usr

# 定期重新扫描 SUID 文件（每 300 秒）
sudo python3 pagecache_guard.py --rescan-interval 300 /usr

# 输出到 syslog
sudo python3 pagecache_guard.py --syslog /usr

# 输出到日志文件
sudo python3 pagecache_guard.py --log-file /var/log/pagecache_guard.log /usr

# 连 root 执行也检查
sudo python3 pagecache_guard.py --check-root /usr
```

## 运行效果

```
2026-05-08 06:57:31 INFO Scanning for SUID/SGID files in: /usr
2026-05-08 06:57:34 INFO Found 21 SUID/SGID files
2026-05-08 06:57:34 INFO   SUID/SGID: /usr/bin/su
2026-05-08 06:57:34 INFO   SUID/SGID: /usr/bin/sudo
...
2026-05-08 06:57:34 INFO Guard active [ENFORCE] (event_size=24, check_root=False)

# 被篡改的 /usr/bin/su 被检测并拦截:
2026-05-08 06:57:38 WARNING [ALERT] BLOCKED pid=2677362 uid=1000 /usr/bin/su
                            (page cache tampered at offset 0)
```

用户侧：

```bash
$ /usr/bin/su
bash: /usr/bin/su: 不允许的操作  (exit 126)
```

## 系统要求

| 组件 | 推荐 | 最低要求 | 说明 |
|------|------|----------|------|
| **内核** | >= 5.0 | >= 2.6.37 | 5.0+ 支持 `FAN_OPEN_EXEC_PERM`；旧内核自动降级到 `FAN_OPEN_PERM` |
| **RHEL 8** | 4.18.0 | — | `FAN_OPEN_EXEC_PERM` 已通过 RHEL backport 支持（已验证） |
| **文件系统** | ext4 / XFS / Btrfs | — | 须支持 `O_DIRECT` |
| **权限** | root | `CAP_SYS_ADMIN` | fanotify 权限事件需要 |
| **Python** | 3.6+ | 3.6 | 使用 f-string 和 `os.splice` |

## 检测覆盖范围

fanotify Guard 基于 `FAN_OPEN_EXEC_PERM` 拦截 `execve()`，设计上仅覆盖 SUID/SGID 二进制执行。以下是与实际宿主机攻击路径的对照（PoC 见 `poc/host-attacks/`）：

| 攻击路径 | fanotify Guard | O_DIRECT 定期扫描 | 原因 |
|---------|:--------------:|:----------------:|------|
| SUID/SGID 二进制覆写 | ✅ | ✅ | execve 时实时拦截 |
| `/etc/passwd` UID 篡改 | ❌ | ✅ | 配置文件，被 `open()`+`read()` 读取 |
| PAM 模块认证绕过 | ❌ | ✅ | 共享库通过 `dlopen()` 加载 |
| 共享库 Live-Patching | ❌ | ✅ | 通过 `mmap()` 映射，非 execve |
| `/etc/profile` 命令注入 | ❌ | ✅ | 登录 Shell `source` 读取 |
| Cron 脚本篡改 | ❌ | ✅ | 由 crond 通过 `execve()` 执行，但不属于 SUID 文件 |
| `ld.so.preload` 路径劫持 | ❌ | ✅ | 动态链接器在进程启动时读取 |
| 容器逃逸（层共享） | ❌ | ✅ | overlay lower layer 定期扫描 |

Guard 解决最危急的场景——阻止被篡改的 SUID 二进制执行提权。其余 6 条宿主机路径和容器场景，通过 O_DIRECT 定期扫描覆盖。扫描优先级：PAM 模块和共享库（`/lib64/security/`、`/lib64/*.so`）> 关键配置文件（`/etc/passwd`、`/etc/profile`、`/etc/ld.so.preload`）> cron 脚本和容器 lower layer。

## PoC 脚本

| 脚本 | 用途 |
|------|------|
| `poc/poc_marker.py` | 触发 Copy Fail 向文件页缓存写入 `0xDEADBEEF` 标记 |
| `poc/verify_marker.py` | 验证标记是否可见（测试跨容器页缓存共享） |
| `poc/shocker_copyfail.py` | Shocker + Copy Fail 组合攻击 — 通过 `CAP_DAC_READ_SEARCH` 实现容器逃逸 |
| `poc/host-attacks/` | **7 条宿主机攻击路径 PoC**：passwd UID / PAM 绕过 / 共享库 / profile 注入 / cron 脚本 / ld.so.preload / SUID ELF（详见 [README](poc/host-attacks/README.md)） |

**警告**: PoC 脚本需要未修补的内核，仅用于授权安全研究。

## 技术细节

### 为什么用 O_DIRECT？

页缓存覆写攻击直接修改内核内存中的文件缓存，不经过 VFS 写路径。这意味着：

- **不设置脏页标记** — `sync` 不会将篡改刷回磁盘
- **文件完整性监控失效** — AIDE/OSSEC 等通过页缓存读取，看到的是篡改后的数据
- **镜像扫描失效** — Trivy/Grype 扫描的是压缩层 blob，与页缓存无关
- **`docker diff` 失效** — 只检查 overlayfs upper layer 变更
- **fs-verity 失效** — 仅在磁盘→缓存读取时验证，不检测缓存内篡改

`O_DIRECT` 是唯一的标准 POSIX 方式来绕过页缓存直接读磁盘，因此是检测此类攻击的唯一可靠手段。

### 为什么跳过 root？

root 已有最高权限，SUID 提权对 root 无意义。跳过 root 减少开销并避免系统服务产生噪声。

在容器逃逸场景中，攻击者（容器内 root）篡改 page cache，但**受害者**是宿主机上的普通用户执行被篡改的 SUID 文件 — Guard 正确拦截此场景。

### 合法更新期间的误报

当 SUID 文件正在被包管理器更新时，页缓存与磁盘可能暂时不一致。但 Linux 内核通过 `deny_write_access()` 阻止执行存在活跃写入 FD 的文件（`ETXTBSY`），因此合法更新不会触发误报拦截。

## 相关研究

- [Copy Fail — xint.io](https://xint.io/posts/copy-fail-cve-2026-31431/) — 漏洞原始披露与技术分析
- [CVE-2026-31431 on NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
- [内核修复 commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a664bf3d603d)

## License

MIT
