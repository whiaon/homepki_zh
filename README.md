# homepki

一款可自托管的轻量 Web 应用，用于搭建你自己的私有 TLS 证书颁发机构。可签发、轮换、吊销、下载证书；配置部署目标；管理通行短语 ——**全部在浏览器内完成**。无需单独安装`homepki`命令行工具：单个 Docker 容器即可运行服务并提供 Web 界面。

## 适用场景

**项目诞生初衷：为 [Tailscale](https://tailscale.com/) 网络内设备提供 HTTPS**。 如果你给内网 Tailscale 设备设置友好域名，例如`nas`、`media`或`pi.tail-scale.ts.net`，Let's Encrypt 无法签发这类域名证书 —— 它们不存在于公共 DNS。但只要在每台设备信任 homepki 根证书，你的 Tailscale 内网所有服务就能获得正规 HTTPS，不再弹出浏览器安全警告。证书可使用设备实际访问名称：短 MagicDNS 域名、`*.lan`别名、原始 Tailscale 内网 IP。

家庭实验室场景同样存在这类需求：`nas.lan`的 NAS、`192.168.x.x`路由器管理页面、Home Assistant、自托管 Git 服务器。Let's Encrypt 无法签发这类内网证书，浏览器警告反复出现，网上复制的 openssl 命令也容易出错。

homepki 补齐了这个缺口：

- 一套**根 CA**，在你的设备上一次性信任即可。
- **终端证书**，用于各项独立服务，自带标准 SAN（`nas.lan`、`192.168.1.10`、MagicDNS 域名），有效期短，方便定期轮换。
- **部署目标**：自动将证书和私钥写入磁盘，适配 nginx / Caddy /haproxy 路径，还可选择执行`nginx -s reload`重载服务。
- 所有签发证书内置**公开 CRL 吊销端点**，吊销证书后，受信任设备可以获取吊销信息。
- 数据静态加密，密钥由你设置的通行短语保护。锁定应用后，内存中的密钥会被清除；磁盘上的私钥无法读取，直到重新解锁。

项目刻意保持精简：单二进制程序、单个 SQLite 数据库、单用户。**不提供 ACME 服务器、不支持多租户 CA 面板**。如果你需要这些功能，请使用 [step-ca](https://github.com/smallstep/certificates) 或 [EJBCA](https://www.ejbca.org/)。

## 运行方式

镜像地址：`ghcr.io/klice/homepki`。选择合适标签：`latest`为最新稳定版；`vX.Y.Z`锁定特定版本；`edge`跟随主分支（开发预览版，尚未正式发布）。

### Docker 快速启动

**1. 启动容器**

```
docker run -d \
  --name homepki \
  -p 8080:8080 \
  -v homepki-data:/data \
  -e CRL_BASE_URL=http://localhost:8080 \
  ghcr.io/klice/homepki:latest
```

**2. 在浏览器打开 Web 管理界面**：http://localhost:8080 首次访问会进入**首次初始化设置**页面，设置通行短语（≥12 字符）并二次确认。务必妥善保存，没有通行短语就无法恢复加密私钥。

**3. 在面板签发第一条证书链**：先创建根 CA，再创建中间 CA，最后为需要保护的服务签发终端证书。全程鼠标点击操作，无需 openssl 命令。

### Docker Compose 部署

如需开机自启，和其他服务一起管理，新建`docker-compose.yml`文件：

```
services:
  homepki:
    image: ghcr.io/klice/homepki:latest
    container_name: homepki
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - homepki-data:/data
    environment:
      # 必填项。客户端用来获取CRL吊销列表的基础地址，签发证书时写入证书内，
      # 验证证书的设备必须能访问该地址。仅本机使用填 http://localhost:8080；
      # 其他内网设备访问，则填写网络内可访问的地址。
      CRL_BASE_URL: http://homepki.lan:8080
      # HTTP服务在容器内监听地址。镜像默认暴露8080端口，仅修改端口映射时才需要改动。
      # CM_LISTEN_ADDR: ":8080"
      # SQLite数据库在容器内存放路径。镜像已声明/data为数据卷，数据挂载到此目录。
      # CM_DATA_DIR: "/data"
      # 如果配置此项，服务启动时自动解锁。适合无人值守服务器，但安全性低于手动在页面输入通行短语。
      # 留空则每次启动需要手动解锁。
      # CM_PASSPHRASE: ""
      # 空闲多少分钟后自动锁定。不设置/填0代表不会自动锁定，需要手动点击锁定或重启容器。
      # CM_AUTO_LOCK_MINUTES: "0"
      # 日志格式：json适合日志收集工具；text适合直接查看日志。
      # CM_LOG_FORMAT: "json"
      # homepki进程在容器内切换使用的UID/GID。入口脚本以root运行，创建对应用户、修改/data目录权限，
      # 之后切换该用户运行程序。默认1000:1000。Unraid系统设置PUID=99 PGID=100可适配appdata目录权限。
      # PUID: "1000"
      # PGID: "1000"
volumes:
  homepki-data:
```

然后执行：

```
docker compose up -d
```

操作和单独 Docker 启动一致，浏览器访问 http://localhost:8080 打开 Web 界面。

### 在设备上信任根证书

创建根 CA 之后，在证书详情页下载`cert.pem`，将它导入各设备的系统信任存储。常用平台导入方法：

- **Linux（Debian/Ubuntu）**：复制文件到 `/usr/local/share/ca-certificates/homepki-root.crt`，执行 `sudo update-ca-certificates`
- **macOS**：双击`.crt`文件 → 钥匙串访问 → 将*使用此证书时*改为*始终信任*
- **Windows**：双击文件 → *安装证书* → *本地计算机* → *将所有证书放入下列存储* → *受信任的根证书颁发机构*
- **Firefox**：自带独立证书库。设置 → 隐私与安全 → 证书 → 查看证书 → 证书颁发机构 → 导入
- **Android / iOS**：搜索对应系统版本的*安装用户证书*教程；新版安卓默认对用户导入根证书标记警告（root 设备除外）

完成后，homepki 基于该根签发的所有证书都会被系统信任，不再弹出安全警告。

## 配置项

全部配置通过环境变量设置

表格

| 变量                   | 默认值   | 说明                                                         |
| ---------------------- | -------- | ------------------------------------------------------------ |
| `CRL_BASE_URL`         | *必填*   | 客户端获取 CRL 吊销列表的基础地址，签发时写入证书            |
| `CM_LISTEN_ADDR`       | `:8080`  | HTTP 服务监听地址                                            |
| `CM_DATA_DIR`          | `/data`  | SQLite 数据库存放路径，建议挂载数据卷                        |
| `CM_PASSPHRASE`        | *未设置* | 设置后容器启动自动解锁；适合无人值守环境，安全性低于手动解锁 |
| `CM_AUTO_LOCK_MINUTES` | *未设置* | 空闲超时自动锁定分钟数；不填 / 填 0 关闭自动锁定             |
| `CM_LOG_FORMAT`        | `json`   | 日志格式，可选`json`或`text`                                 |

## 备份

停止容器后复制数据目录：

```
docker stop homepki
cp -r /var/lib/docker/volumes/homepki-data/_data ~/homepki-backup
docker start homepki
```

容器运行状态下，使用 SQLite 在线备份：

```
docker exec -it homepki \
  sh -c 'sqlite3 /data/homepki.db ".backup /data/backup.db"'
docker cp homepki:/data/backup.db ~/homepki-backup.db
docker exec -it homepki rm /data/backup.db
```

备份文件是标准 SQLite 数据库。恢复时停止容器，替换数据库文件，重启容器即可。

## 搭配反向代理

容器原生在`8080`端口提供 HTTP。一般推荐前置反向代理做 TLS 终结；反向代理使用的证书本身也可以由 homepki 签发。Nginx、Caddy、Traefik、haproxy 均可，homepki 无特殊限制。

若反向代理部署在其他主机，`CRL_BASE_URL`填写**客户端可访问的公网 / 内网地址**，不要填`http://localhost:8080`。

## 功能边界：homepki 不具备的能力

- **不是 ACME 服务器**：不支持 acme.sh、certbot 自动申请证书；需要管理员手动在界面签发。
- **不支持多租户**：单管理员、单通行短语、一套 CA 证书链。
- **v1 版本无独立 JSON/REST API**：浏览器和 curl 访问的是同一套 HTML 页面端点。证书、私钥、CRL 可以直接下载 PEM/DER，可简单脚本自动续期，但没有独立 API 接口。

## 开发者相关

如需阅读设计文档或参与贡献，文档存放在[docs/](docs/)目录：

表格

| 文档                                | 阅读用途                                                     |
| ----------------------------------- | ------------------------------------------------------------ |
| [SPEC.md](docs/SPEC.md)             | 产品范围、技术栈、部署方式、环境变量，推荐先读               |
| [LIFECYCLE.md](docs/LIFECYCLE.md)   | 锁定 / 解锁、KEK→DEK 密钥加密机制、密钥轮换、证书吊销、CRL 生成逻辑 |
| [STORAGE.md](docs/STORAGE.md)       | SQLite 表结构、数据库迁移、事务、备份方案                    |
| [API.md](docs/API.md)               | 路由、请求 / 响应结构、状态码、幂等性说明                    |
| [COLD_ROOTS.md](docs/COLD_ROOTS.md) | v2 版本规划：根密钥冷存储，使用独立数据库离线保存根密钥      |

项目内置 devcontainer，在 VS Code 安装 Dev Containers 插件打开仓库，即可获得完整编译环境。执行`make help`查看常用编译命令。

## 许可证

[MIT](LICENSE)
