# spring-security-demo

![](https://img.shields.io/static/v1?label=Spring%20Boot&message=4.1.1&color=green)
![](https://img.shields.io/static/v1?label=Spring%20Security&message=7.1.1&color=blue)
![](https://img.shields.io/static/v1?label=Java&message=21&color=orange)

> Spring Security 核心概念与多认证模式演示工程

---

## 👥 测试账号

| 用户名 | 密码 | 具备权限/角色 | 说明 |
|:---|:---|:---|:---|
| `admin` | `admin` | `admin` | 管理员账号，拥有 `/admin` 及细粒度 read 权限 |
| `test` | `test` | `test` | 普通测试账号，拥有 `/test` 权限 |

*密码即用户名自身，在内存中完成 DelegatingPasswordEncoder 加密与校验。*

---

## 🚀 快速启动与功能测试

### 1. 运行项目
```bash
mvn spring-boot:run
```
默认服务端口：`18000`

### 2. 核心端点
- **表单登录**：http://localhost:18000/login.html（处理路径 `/your-login-path`，默认跳转 `/info`，支持 Remember-Me）
- **系统退出**：http://localhost:18000/logout.html（退出测试页面，演示表单及 Fetch 调用 `POST /logout`）
- **JSON 登录**：http://localhost:18000/custom-login.html（`POST /your-custom-login-path`，接收 JSON 凭据，返回 Session ID）
- **Token 认证**：http://localhost:18000/custom-token-login.html（`POST /your-custom-token-login-path`，Header 携带 `token` 进行认证）
- **公共接口**：http://localhost:18000/info、http://localhost:18000/info/appName（无需认证）
- **管理员接口**：http://localhost:18000/admin（仅限 `admin` 权限）
- **测试员接口**：http://localhost:18000/test（仅限 `test` 权限）
- **受保护接口**：http://localhost:18000/app（登录用户可访问）

---

## 📚 权限控制与方法安全注解

```java
@PreAuthorize("hasAuthority('admin')")              // 方法调用前鉴权
@PostAuthorize("returnObject.owner == principal.username") // 方法调用后对象归属校验
@PreAuthorize("hasPermission('target-id', 'read')") // 自定义 PermissionEvaluator 细粒度权限校验
@Secured("ROLE_USER")                              // 角色级别鉴权
@PreFilter / @PostFilter                           // 集合入参及返回值过滤
```

---

## 🛠️ 测试与设计资源

- **HTTP Client 脚本**：根目录 `http/` 下提供了完整的 IntelliJ IDEA `.http` 测试套件（涵盖公开放行、表单登录、JSON登录、Token认证、方法鉴权、CSRF 防护、退出等），可直接批量运行。
- **架构时序图**：根目录 `docs/` 下提供了过滤器链、认证流程、鉴权流程及类关系的 PlantUML 设计图。

---

## 📖 参考文档

- [Spring Security 官方文档](https://docs.spring.io/spring-security/reference/)
- [Spring Boot 整合 Spring Security 最简单的用法](https://www.toutiao.com/i7013356585607086625)

---

## 📦 CI/CD 与 Docker 镜像

`.github/workflows/build.yml` 定义 4 个 Job：

| Job | 触发条件 | 职责 |
|-----|----------|------|
| `build` | push (master/main/v\*) + PR | Dragonwell JDK 21 编译与测试，上传 `target/spring-security-demo.jar` 为 artifact（保留 30 天） |
| `release` | tag `v*` | 由 artifact 创建 GitHub Release，自动生成 release notes |
| `docker-ghcr` | tag `v*` | 多架构（linux/amd64 + linux/arm64）构建并推送到 GitHub Container Registry（`ghcr.io`），打 `:<VERSION>` 与 `:latest` |
| `docker-hub` | tag `v*` | 多架构（linux/amd64 + linux/arm64）构建并推送到 Docker Hub（`javawiki/spring-security-demo`），打 `:<VERSION>` 与 `:latest` |

### 仓库 Secrets 配置

在 GitHub 仓库 **Settings → Secrets and variables → Actions** 中配置：

| Secret | 必填 | 说明 |
|--------|:----:|------|
| `DOCKERHUB_USERNAME` | ✓ | Docker Hub 用户名（如 `javawiki`） |
| `DOCKERHUB_TOKEN` | ✓ | Docker Hub Access Token，从 [hub.docker.com/settings/security](https://hub.docker.com/settings/security) 生成，需 `Read & Write` 权限 |
| `GITHUB_TOKEN` | - | GitHub Actions 自动注入，**无需手动创建**，由 workflow 的 `permissions: packages: write` 自动赋权 |
