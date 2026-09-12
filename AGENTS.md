# 开发规范

本文档供 **AI 编码助手** 阅读。

## 环境

- Java 21、Maven 3.9+、Spring Boot 4.1.1、Spring Security 7.1.1
- 本地端口：`18000`（`http/http-client.env.json` 的 `dev`）
- Docker：`SERVER_PORT=18000`
- 核心依赖：`spring-boot-starter-security`、`spring-boot-starter-web`、`spring-boot-starter-thymeleaf`、`fastjson2`、`lombok`

## 命令

```bash
mvn spring-boot:run
mvn test
mvn clean package -DskipTests
```

产物：`target/spring-security-demo.jar`。CI 使用 package 命令（Dragonwell 21）。

## 目录

```
src/main/java/cn/netbuffer/springsecuritydemo/
├── SpringSecurityDemoApplication.java   # 启动入口与基础 Bean 配置
├── auth/                                # 自定义认证体系
│   ├── provider/                        # CustomAuthenticationProvider
│   └── token/                           # CustomTokenAuthenticationToken
├── component/                           # CustomLogoutHandler 等组件
├── config/                              # SpringSecurityConfig 等核心安全配置
├── controller/                          # Web 控制器（测试端点、受保护端点等）
├── filter/                              # 过滤器（CustomLoginFilter、CustomTokenAuthenticationFilter、CsrfCookieFilter）
├── listener/                            # AuthenticationEventListener 事件监听
├── permission/                          # SsdPermissionEvaluator 细粒度权限判定
├── pojo/                                # 实体与数据模型
└── service/                             # CustomUserDetailsService 用户详情服务
src/test/java/…                          # 单元与集成测试（TestAuthentication、SpringSecurityDemoApplicationTests）
http/                                    # IntelliJ HTTP Client 脚本套件（按场景分模块编号）
docs/                                    # PlantUML 架构、认证流程、时序图
src/main/resources/public/               # 前端静态页面（表单/JSON/Token 登录页、403页等）
```

## 约定

- 命名：`*Controller`、`*Filter`、`*Provider`、`*Token`、`*Config`、`*Service`
- 认证与安全配置统一在 `config/SpringSecurityConfig` 及 `auth/`、`filter/` 下维护，遵循 Spring Security 7+ DSL 规范
- 测试：使用 `@SpringBootTest` 与 `spring-security-test`，覆盖认证鉴权场景
- 保持 demo 规模与聚焦：核心演示 Spring Security 认证鉴权模型、过滤器链、方法级安全与 CSRF 防护，不随意引入大型 ORM 或外置数据库
- 不要随意升级 Spring Boot / Spring Security / Java 大版本；无必要不调整已有包结构

## 联改

| 改动 | 同步更新 |
|------|----------|
| 对外 HTTP 接口 / 认证路径 | `http/*.http`、`README.md`、前端页面表单 action/fetch 路径 |
| 端口 | `http/http-client.env.json`、`application.yaml`、Dockerfile、`docker-compose.yml`、`README.md` |
| 安全配置 / 角色权限模型 | `CustomUserDetailsService`、`SpringSecurityConfig`、测试用例、`README.md` 测试账号表 |
| 过滤器或认证流程变更 | `docs/*.puml` 相关流程与时序图 |

## 提交

Conventional Commits：`<type>: <说明>`（英文祈使句、小写开头、无句末句号）。

类型：`feat` `fix` `docs` `refactor` `test` `chore` `perf`

- 一事一提交；相关 README/HTTP/文档改动可同提交
- 用户未要求时禁止 `git commit` / `git push`
- 禁止提交密钥与敏感配置

## CI / 发布

`.github/workflows/build.yml`：推送/PR 到 `master`/`main` → 构建并上传 jar；标签 `v*` → GitHub Release + `ghcr.io`。未经要求勿改 workflow 权限或触发条件。

## 安全与边界

- 不把密钥或敏感信息写入仓库或提交
- 不把 Agent 专用规则写进 `README.md`
- 改动保持聚焦，禁止顺手大重构
