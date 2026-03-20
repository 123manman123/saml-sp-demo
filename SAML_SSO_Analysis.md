# NGIAM SAML 单点登录流程结构分析

## 一、整体架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              NGIAM IDP                                   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    server-common-sso 模块                        │   │
│  │  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐   │   │
│  │  │SsoLoginCtrl │───▶│ProcessorFact │───▶│  SamlProcessor   │   │   │
│  │  │  /web/login │    │    ory       │    │   (SAML 处理器)   │   │   │
│  │  │    /sso     │    └──────────────┘    └────────┬─────────┘   │   │
│  │  └─────────────┘                                  │             │   │
│  │                                                   ▼             │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │ DbMetadataProvider ──▶ 从数据库加载 SP 元数据缓存       │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ SAML Response (POST)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        saml-sp-demo (SP 测试应用)                        │
│  ┌──────────────────┐    ┌───────────────────┐    ┌────────────────┐  │
│  │ SecurityConfig   │    │SamlRelyingParty   │    │ UserController │  │
│  │ (Spring Security)│───▶│Config (SP 配置)   │───▶│  (用户信息)    │  │
│  └──────────────────┘    └───────────────────┘    └────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 二、核心类详解

### 1. SamlAuthConfigDTO (server-common-core)

**位置**: `ngiam/server-common-core/src/main/java/com/jingantech/server/common/core/resource/vo/sso/SamlAuthConfigDTO.java`

**职责**: SAML 认证配置数据传输对象
- 存储 SP 配置：`entityId`（实体ID）、`entityBaseUrl`（应用地址）、`cert`（加密证书）
- 生成 IDP 元数据（IDPSSODescriptor 格式）
- 调用 `SamlMetadataGenerator` 生成元数据 XML

```java
// 关键方法
private void generateMetadata() {
    // 生成 IDP 元数据供 SP 使用
    generator.setEntityId(SamlConsts.IDP_ENTITY);  // "idp.jingantech.com"
    generator.setEntityBaseUrl(getmedataBaseUrl(this.entityId));
    generator.setJksCert(SamlConsts.getIdpCert());  // 加载签名证书
}
```

---

### 2. SamlMetadataGenerator (server-common-core)

**位置**: `ngiam/server-common-core/src/main/java/com/jingantech/server/common/core/resource/vo/sso/util/SamlMetadataGenerator.java`

**职责**: 生成 SAML 元数据（基于 OpenSAML 3.4.6）
- 生成 `IDPSSODescriptor` 格式元数据
- 包含：KeyDescriptor（签名/加密证书）、SingleSignOnService、NameIDFormat

```xml
<!-- 生成的元数据结构 -->
<md:EntityDescriptor entityID="idp.jingantech.com">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">...</md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">...</md:KeyDescriptor>
    <md:SingleSignOnService Binding="HTTP-Redirect" Location="..."/>
    <md:SingleSignOnService Binding="HTTP-POST" Location="..."/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
```

---

### 3. DbMetadataProvider (server-common-sso-access-app)

**位置**: `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/saml/metadata/DbMetadataProvider.java`

**职责**: 从数据库加载和缓存 SP 元数据
- 启动时加载所有 SAML 应用配置
- 定时任务每分钟刷新缓存
- 动态构建 `SPSSODescriptor` 元数据

```java
// 核心流程
@PostConstruct
public void init() {
    loadMetadataFromDb();  // 启动时加载
}

@Scheduled(cron = "0 0/1 * * * * ")
public void loadMetadataFromDbBySchedule() {
    loadMetadataFromDb();  // 定时刷新
}
```

---

### 4. SamlProcessor (server-common-sso-access-app)

**位置**: `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/controller/sso/SamlProcessor.java`

**职责**: SAML 响应处理器（IDP 端核心）

**核心方法**:

| 方法 | 功能 |
|------|------|
| `signOn()` | 执行 SAML 单点登录 |
| `getResponse()` | 生成 SAML Response |
| `getAssertion()` | 生成断言（包含用户属性） |
| `signAssertion()` | 对断言签名（SHA256） |
| `encryptAssertion()` | 加密断言（AES-256 + RSA-OAEP） |
| `sendResponse()` | 发送 POST 绑定响应 |

```java
// SAML 响应生成流程
Response samlResponse = getResponse(...);  // 1. 生成 Response
signAssertion(assertion);                   // 2. 签名断言
EncryptedAssertion encrypted = encryptAssertion(assertion, credential);  // 3. 加密断言
sendResponse(response, samlResponse, acsUrl, relayState);  // 4. 发送响应
```

---

### 5. SsoLoginController (server-common-sso-access-app)

**位置**: `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/controller/authentication/SsoLoginController.java`

**职责**: 单点登录入口控制器
- `/web/login/sso` - SSO 统一入口
- 根据 `protocal` 参数路由到不同处理器（SAML/CAS/OAuth等）

```java
@RequestMapping(value = "/sso", method = RequestMethod.GET)
public void sso() {
    String protocal = request.getParameter("protocal");
    SsoProcessor ssoProcessor = processorFactory.getProcessor(protocal);
    ssoProcessor.sso(request, response, context);
}
```

---

### 6. CallonAppsController (server-common-sso-access-app)

**位置**: `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/saml/controller/CallonAppsController.java`

**职责**: WEB 端单点登录 API
- `/v1/callonApps/{spId}/{accountId}` - 执行单点登录并返回 SAML 响应

---

### 7. LoginService (server-common-sso-access-app)

**位置**: `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/service/sso/LoginService.java`

**职责**: 登录业务服务
- 检查用户账户有效性
- MFA 验证
- 调用 `SsoProcessor` 生成 SAML 响应

---

## 三、saml-sp-demo 测试项目结构

```
saml-sp-demo/
├── src/main/java/com/jingantech/saml/sp/
│   ├── SamlSpApplication.java          # 启动类
│   ├── config/
│   │   ├── SecurityConfig.java         # Spring Security 配置
│   │   └── SamlRelyingPartyConfig.java # SP 配置（证书、IDP 信任）
│   └── controller/
│       ├── HomeController.java         # 首页
│       ├── UserController.java         # 用户信息展示
│       └── MetadataController.java     # SP 元数据接口
├── src/main/resources/
│   └── application.yml                 # 配置文件
└── generate-certs.bat/sh               # 证书生成脚本
```

**关键配置**:
```yaml
saml:
  sp:
    entity-id: "samltest"
    acs-location: "http://localhost:7575/login/saml2/sso/ngiam"
  idp:
    entity-id: "idp.jingantech.com"
    sso-url: "http://sso.n.jingantech.com/access-app-sso/v8/web/login/sso?appCode=samltest"
```

---

## 四、SAML 单点登录流程时序图

```
┌──────┐          ┌─────────┐         ┌──────────┐        ┌──────────────┐
│ User │          │saml-sp- │         │SsoLogin  │        │SamlProcessor │
│      │          │  demo   │         │Controller│        │              │
└──┬───┘          └────┬────┘         └────┬─────┘        └──────┬───────┘
   │                   │                   │                     │
   │  1. 访问受保护资源  │                   │                     │
   │──────────────────▶│                   │                     │
   │                   │                   │                     │
   │                   │ 2. 重定向到 IDP    │                     │
   │◀──────────────────│                   │                     │
   │                   │                   │                     │
   │ 3. GET /web/login/sso?appCode=xxx     │                     │
   │──────────────────────────────────────▶│                     │
   │                   │                   │                     │
   │                   │                   │ 4. 检查登录状态     │
   │                   │                   │    未登录→跳转登录页│
   │                   │                   │                     │
   │ 5. 用户登录 + MFA │                   │                     │
   │──────────────────────────────────────▶│                     │
   │                   │                   │                     │
   │                   │                   │ 6. callonApps()     │
   │                   │                   │────────────────────▶│
   │                   │                   │                     │
   │                   │                   │ 7. getSPSSODescriptor│
   │                   │                   │    (从 DbMetadataProvider)│
   │                   │                   │                     │
   │                   │                   │ 8. 生成 SAML Response│
   │                   │                   │    - Assertion      │
   │                   │                   │    - 签名           │
   │                   │                   │    - 加密           │
   │                   │                   │                     │
   │ 9. POST SAMLResponse (HTML Form)      │                     │
   │◀──────────────────────────────────────│◀────────────────────│
   │                   │                   │                     │
   │ 10. POST /login/saml2/sso/ngiam       │                     │
   │──────────────────▶│                   │                     │
   │                   │                   │                     │
   │                   │ 11. 验证签名       │                     │
   │                   │     解密断言       │                     │
   │                   │     创建 Session   │                     │
   │                   │                   │                     │
   │ 12. 重定向到用户页面│                   │                     │
   │◀──────────────────│                   │                     │
   │                   │                   │                     │
```

---

## 五、关键特性

| 特性 | 实现方式 |
|------|---------|
| **签名算法** | RSA-SHA256（OpenSAML 3.4.6 推荐） |
| **加密算法** | AES-256（数据加密）+ RSA-OAEP（密钥传输） |
| **证书管理** | JKS 密钥库（idp.jks），支持多别名 |
| **元数据格式** | IDPSSODescriptor（IDP）+ SPSSODescriptor（SP） |
| **绑定方式** | HTTP-POST（主要）、HTTP-Redirect |
| **属性传递** | userId、tenant、userApiKey + 自定义扩展属性 |

---

## 六、配置数据流向

```
┌─────────────────┐
│ 数据库          │
│ ngiam-db.       │
│ resource_sso    │
│ (configs字段)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────────┐
│DbMetadataProvider│─────▶│ Memory Cache     │
│ (定时刷新)       │      │ Map<entityId,    │
└─────────────────┘      │   MetadataResolver│
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ SamlProcessor    │
                         │ 获取 SP 元数据    │
                         │ - 加密证书        │
                         │ - ACS 地址        │
                         └──────────────────┘
```

---

## 七、类关系图

```
┌──────────────────────────────────────────────────────────────────┐
│                        SsoProcessor (接口)                        │
│  - name(): String                                                 │
│  - processor(...): Object                                         │
│  - sso(...): void                                                 │
│  - destination(...): String                                       │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                │ implements
                                │
┌───────────────────────────────┴──────────────────────────────────┐
│                     AbstractProcessor (抽象类)                    │
│  - property(...): String                                         │
│  - constructUrl(...): String                                     │
│  - redirectPage(...): void                                       │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                │ extends
                                │
┌───────────────────────────────┴──────────────────────────────────┐
│                        SamlProcessor                              │
│  - signOn(...): void                                             │
│  - getResponse(...): Response                                    │
│  - getAssertion(...): Assertion                                  │
│  - signAssertion(...): void                                      │
│  - encryptAssertion(...): EncryptedAssertion                     │
│  - sendResponse(...): void                                       │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                     ProcessorFactory                              │
│  - ssoProcessors: List<SsoProcessor>                             │
│  + getProcessor(protocol): SsoProcessor                          │
└──────────────────────────────────────────────────────────────────┘
```

---

## 八、文件路径索引

| 类名 | 文件路径 |
|------|---------|
| SamlAuthConfigDTO | `ngiam/server-common-core/src/main/java/com/jingantech/server/common/core/resource/vo/sso/SamlAuthConfigDTO.java` |
| SamlMetadataGenerator | `ngiam/server-common-core/src/main/java/com/jingantech/server/common/core/resource/vo/sso/util/SamlMetadataGenerator.java` |
| SamlConsts | `ngiam/server-common-core/src/main/java/com/jingantech/server/common/core/access/constant/SamlConsts.java` |
| DbMetadataProvider | `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/saml/metadata/DbMetadataProvider.java` |
| SamlProcessor | `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/controller/sso/SamlProcessor.java` |
| SsoProcessor | `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/controller/sso/SsoProcessor.java` |
| AbstractProcessor | `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/controller/sso/AbstractProcessor.java` |
| ProcessorFactory | `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/controller/sso/ProcessorFactory.java` |
| SsoLoginController | `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/controller/authentication/SsoLoginController.java` |
| CallonAppsController | `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/saml/controller/CallonAppsController.java` |
| LoginService | `ngiam/server-common-sso/server-common-sso-access-app/src/main/java/com/jingantech/server/app/sso/service/sso/LoginService.java` |
| SecurityConfig (SP) | `saml-sp-demo/src/main/java/com/jingantech/saml/sp/config/SecurityConfig.java` |
| SamlRelyingPartyConfig (SP) | `saml-sp-demo/src/main/java/com/jingantech/saml/sp/config/SamlRelyingPartyConfig.java` |
| UserController (SP) | `saml-sp-demo/src/main/java/com/jingantech/saml/sp/controller/UserController.java` |

---

## 九、依赖关系

### NGIAM IDP 依赖 (OpenSAML 3.4.6)

```xml
<dependency>
    <groupId>org.opensaml</groupId>
    <artifactId>opensaml-core</artifactId>
    <version>3.4.6</version>
</dependency>
<dependency>
    <groupId>org.opensaml</groupId>
    <artifactId>opensaml-saml-api</artifactId>
    <version>3.4.6</version>
</dependency>
<dependency>
    <groupId>org.opensaml</groupId>
    <artifactId>opensaml-saml-impl</artifactId>
    <version>3.4.6</version>
</dependency>
```

### saml-sp-demo 依赖 (Spring Security SAML2)

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-saml2-service-provider</artifactId>
</dependency>
```

---

*文档生成时间: 2026-03-20*
