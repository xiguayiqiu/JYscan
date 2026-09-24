# JYscan

**JYscan** 是GYscan 的 **Java 移植版**，对应来源为 [GYscan](https://github.com/xiguayiqiu/GYscan) 的Go版源码 它是一款面向授权测试与安全研究的命令行工具箱，侧重资产探测、漏洞检测与安全验证。

- 命令行驱动，支持模块化命令与分组。
- 跨平台 Java 实现，通过 Maven 构建，可直接运行或打包为可执行 JAR。
- 支持中英文界面（依赖 `JYSCAN_LANG` / `LANG` 环境变量或 `--lang` 参数）。

> 警告：仅用于授权测试，严禁未授权使用。

---

## 名称与版本

- 项目：JYscan
- 版本标识（内置）：`v3.6-free`
- CLI 版本输出示例：

  ```
  jyscan-free version v3.6-free
  ```

---
**注意：在Windows中请先设置chcp 65001 之后再使用JYscan！**

## 特性

- 以命令为中心的操作模型，命令按用途分组。
- 支持常见资产与安全分析任务，例如：
  - 网络扫描与探测
  - DNS 查询与反向解析
  - CDN / 云服务商识别
  - 子域名枚举
  - 网站目录扫描
  - SSL/TLS 配置检查
  - Whois 查询
  - WAF 识别
  - Sitemap 分析
  - 本地信息与进程信息收集
  - 密码字典生成与社会工程学辅助
  - 关于工具本身的信息显示

---

## 命令分组

当前命令按分组显示，具体命令以实际构建与注册为准。常见分组包括：

- **通用**
  - `about`：关于工具本身的综合信息
- **密码学工具**
  - `crunch`：基于字符模式的字典生成功能
  - `cupp`：社会工程学辅助的密码生成
  - `passwd`：weakpass 全功能 —— API 13 端点（字典列表/下载、哈希查询、前缀检索、规则变异生成）+ 站内全目录（`-l [N]` 合并 1690+ 条、行首带序号，N=只显示前 N 条（少抓页更快）；`-d` 在 API 无此名时回退 .7z/.gz 直链下载）
- **网络扫描工具**
  - `dirscan`：网站目录扫描
  - `route`：路由跳数检测
  - `scan`：网络扫描，包含主机发现、端口扫描、服务识别及 WAF/假死检测
  - `ssl`：SSL/TLS 配置检测
  - `whois`：Whois 查询
  - `dns`：DNS 查询（多种类型与反向解析）
  - `cdn`：CDN / 云提供商指纹识别
- **信息收集工具**
  - `process`：进程与服务信息收集
  - `userinfo`：本地用户与组分析
  - `sub`：子域名枚举（字典 + DNS）
  - `sitemap`：Sitemap 分析
- **Web 安全工具**
  - `waf`：WAF 识别
  - `webshell`：WebShell 生成功能

---

## 构建与运行

### 先决条件

- JDK（推荐 17+，以匹配编译释放层级）
- Maven

### 编译

```bash
mvn clean compile -DskipTests
```

### 打包可执行 JAR

```bash
mvn package -DskipTests
```

打包后的可执行 JAR 位于 `target/JYscan-1.0-SNAPSHOT.jar`（具体文件名可能随版本变化）。  

### 运行方式

#### 直接执行 JAR

```bash
java -jar target/JYscan-1.0-SNAPSHOT.jar --help
java -jar target/JYscan-1.0-SNAPSHOT.jar <command> --help
```

#### 使用 Maven 执行

```bash
mvn exec:java -Dexec.args="--help"
mvn exec:java -Dexec.args="scan --help"
```

> 实际命令名与选项请以 `jyscan help` 与 `jyscan help <command>` 输出为准。

---

## 全局选项

常用全局控制参数（可与命令共用）：

- `--lang string`：界面语言，例如 `zh` / `en`。  
- `--no-banner`：不显示启动横幅。  
- `--no-color`：禁用颜色输出。  
- `-q, --silent`：静默模式。  
- `-v, --verbose`：显示详细输出。  
- `-V, --version`：显示版本信息。  

语言优先顺序通常为：

1. `--lang` 参数  
2. `JYSCAN_LANG` 环境变量  
3. `LANG` 环境变量  
4. 默认语言  

---

## 命令列表示意（以实际注册为准）

当前可见命令示例：

| 分组 | 命令 | 简要说明 |
|------|------|----------|
| 通用 | about | 关于工具 |
| 密码学工具 | crunch | 字典生成 |
| 密码学工具 | cupp | 社工密码生成 |
| 密码学工具 | passwd | weakpass 全功能（API+站内全目录/直链下载/查询/检索/生成） |
| 网络扫描工具 | dirscan | 目录扫描 |
| 网络扫描工具 | route | 路由跳数 |
| 网络扫描工具 | scan | 网络扫描 |
| 网络扫描工具 | ssl | SSL/TLS 检测 |
| 网络扫描工具 | whois | Whois 查询 |
| 网络扫描工具 | dns | DNS 查询 |
| 网络扫描工具 | cdn | CDN/云识别 |
| 信息收集工具 | process | 进程与服务信息 |
| 信息收集工具 | userinfo | 本地用户/组信息 |
| 信息收集工具 | sub | 子域名枚举 |
| 信息收集工具 | sitemap | Sitemap 分析 |
| Web 安全工具 | waf | WAF 识别 |
| Web 安全工具 | webshell | WebShell 生成 |

---

## 技术栈（以实现为准）

本项目为 Java 实现，核心依赖包括但不限于：

- Picocli（命令行）
- Jackson（JSON 序列化/反序列化）
- Jsoup（HTML 处理）
- SnakeYAML（YAML 解析）
- dnsjava（DNS 查询）
- JNA / JNA-platform（原生调用相关能力）

请以 `pom.xml` 为准。

---

## 语言与本地化

界面语言可通过参数或环境变量切换。命令说明与提示会随选中的语言显示不同文字。

---

## 授权与免责声明

- 本工具仅用于授权测试与安全评估。
- 未经授权对目标进行扫描、探测或其他操作是违法行为。
- 使用者应确保自身行为符合相关法律法规与目标授权范围。

关于原版 GYscan 的授权协议、版权与免责说明，请参阅 [README-GYscan.md](README-GYscan.md)。

---

## 项目状态

- 本 README 反映的是当前已知命令与基础用法。
- 命令列表、选项与说明可能随开发进度变化，请以实际 `jyscan help` 输出为准。
- 某些功能可能尚未完全实现或仅部分提供，具体行为以代码与运行结果为准。

---

## 延伸阅读

- `jyscan help`
- `jyscan help <command>`
- `pom.xml`
- [GYscan](https://github.com/xiguayiqiu/GYscan/README)（GYscan 原版介绍、上下文与对外信息参考）
