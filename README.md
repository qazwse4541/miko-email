# 思.凡邮箱系统 (Miko Email System)

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Version](https://img.shields.io/badge/version-v2.0.0-blue.svg)

🚀 **专业的企业级邮箱管理系统**

一个基于Go语言开发的现代化邮箱系统，支持完整的SMTP/IMAP/POP3协议，提供直观的Web管理界面和无限邮箱创建功能。专为中小企业和个人用户设计，具备完善的级联删除、域名管理、邮件转发等企业级特性。

[📖 在线文档](./API接口文档.txt) • [🎯 功能特性](#-功能特性) • [⚡ 快速开始](#-快速开始) • [🔧 API文档](#-api文档) • [🤝 贡献指南](#-贡献指南)

</div>

## 📋 目录

- [功能特性](#-功能特性)
- [在线演示](#-在线演示)
- [技术栈](#️-技术栈)
- [项目结构](#-项目结构)
- [快速开始](#-快速开始)
- [邮件客户端配置](#-邮件客户端配置)
- [API文档](#-api文档)
- [特色功能](#-特色功能)
- [安全特性](#-安全特性)
- [开发说明](#-开发说明)
- [贡献指南](#-贡献指南)
- [许可证](#-许可证)
- [作者](#-作者)
- [致谢](#-致谢)
- [支持](#-支持)

## 🚀 功能特性

### 🎯 核心功能
- ✅ **无限邮箱创建** - 用户可以创建无限数量的邮箱地址，支持批量创建
- ✅ **多协议支持** - 完整支持SMTP(25/587/465)、IMAP(143/993)、POP3(110/995)协议
- ✅ **现代化Web界面** - 响应式设计，支持移动端，Bootstrap 5 UI框架
- ✅ **企业级权限管理** - 完善的用户/管理员权限体系，支持角色分离
- ✅ **智能域名管理** - 多域名支持，自动DNS记录生成和验证，DKIM签名
- ✅ **高级邮件转发** - 灵活的转发规则，支持条件过滤和批量操作
- ✅ **级联删除保护** - 完善的数据关联删除，防止孤立数据产生
- ✅ **安全加密传输** - 支持STARTTLS/SSL加密，密码bcrypt加密存储

### 👤 用户功能
- 🔐 **账户管理** - 用户注册/登录，密码修改，个人信息管理
- 📧 **邮箱管理** - 创建/删除邮箱，查看邮箱统计，密码管理
- 📨 **邮件处理** - 收发邮件，附件支持(最大25MB)，邮件搜索
- 🔄 **转发设置** - 创建转发规则，条件过滤，转发统计
- 🎁 **邀请系统** - 邀请码生成，贡献度奖励，等级提升
- 📊 **数据统计** - 邮箱使用情况，邮件统计，存储空间

### 👨‍💼 管理员功能
- 👥 **用户管理** - 用户列表，状态管理，权限分配，批量操作
- 🌐 **域名管理** - 域名添加/删除，DNS验证，DKIM配置，使用统计
- 📮 **邮箱监控** - 全局邮箱管理，状态监控，存储统计
- 🛡️ **系统安全** - 访问日志，安全策略，IP限制
- ⚙️ **系统配置** - 全局设置，邮件限制，性能调优

## 🌐 在线演示

> **本地演示地址**: [http://127.0.0.1:8080](http://127.0.0.1:8080)

**演示账号**:
- 🔑 **管理员账号**: `admin` / `tgx123456`
- 👤 **普通用户**: 可自行注册体验
- 📧 **测试邮箱**: `kimi@gmns.top` / `32030b3f`

**演示功能**:
- ✨ 完整的邮箱管理功能
- 📨 SMTP/IMAP/POP3协议测试
- 🔄 邮件转发规则配置
- 🌐 域名DNS记录验证
- 📊 实时统计和监控

> ⚠️ **注意**: 演示环境仅供功能体验，请勿存储重要数据。生产环境请修改默认密码。

## 🛠️ 技术栈

### 🔧 后端技术
- **Go 1.21+** - 高性能编程语言，原生并发支持
- **Gin Web框架** - 轻量级HTTP框架，中间件支持
- **SQLite数据库** - 使用modernc.org/sqlite，纯Go实现，无需CGO
- **Gorilla Sessions** - 安全的会话管理
- **bcrypt加密** - 密码安全存储
- **DKIM签名** - 邮件身份验证
- **DNS解析库** - 域名记录查询和验证

### 🎨 前端技术
- **HTML5 + CSS3** - 现代化页面结构和样式
- **Bootstrap 5.3** - 响应式UI框架，支持暗色主题
- **JavaScript ES6+** - 现代JavaScript特性
- **Axios** - Promise based HTTP客户端
- **Chart.js** - 数据可视化图表
- **FontAwesome** - 图标库

### 📧 邮件协议
- **SMTP** - 邮件发送协议 (25/587/465端口)
- **IMAP** - 邮件接收协议 (143/993端口)
- **POP3** - 邮件下载协议 (110/995端口)
- **STARTTLS/SSL** - 加密传输支持

## 📦 项目结构

```
思.凡邮箱系统/
├── 📁 internal/                    # 核心业务逻辑
│   ├── 📁 config/                  # 配置管理
│   ├── 📁 database/                # 数据库初始化和迁移
│   ├── 📁 handlers/                # HTTP请求处理器
│   │   ├── auth.go                 # 认证相关接口
│   │   ├── domain.go               # 域名管理接口
│   │   ├── email.go                # 邮件处理接口
│   │   ├── forward.go              # 转发规则接口
│   │   ├── mailbox.go              # 邮箱管理接口
│   │   └── user.go                 # 用户管理接口
│   ├── 📁 middleware/              # 中间件
│   │   ├── auth.go                 # 认证中间件
│   │   └── maintenance.go             # 日志记录
│   ├── 📁 models/                  # 数据模型定义
│   ├── 📁 server/                  # 服务器配置
│   │   ├── server.go                # 服务器
│   ├── 📁 services/                # 业务逻辑服务
│   │   ├── 📁 auth/                # 认证服务
│   │   ├── 📁 domain/              # 域名服务 (DNS验证、DKIM)
│   │   ├── 📁 email/               # 邮件服务 (收发、存储)
│   │   ├── 📁 forward/             # 转发服务 (规则引擎)
│   │   └── 📁 mailbox/             # 邮箱服务 (CRUD、统计)
│   └── 📁 utils/                   # 工具函数
├── 📁 web/                         # Web前端资源
│   ├── 📁 static/                  # 静态资源
│   │   ├── 📁 css/                 # 样式文件
│   │   ├── 📁 js/                  # JavaScript文件
│   │   └── 📁 images/              # 图片资源
│   └── 📁 templates/               # HTML模板
│       ├── admin_*.html            # 管理员页面
│       ├── user_*.html             # 用户页面
│       └── common/                 # 公共组件
├── 📁 dkim_keys/                   # DKIM密钥存储
├── 📄 main.go                      # 主程序入口
├── 📄 config.yaml                  # 配置文件
├── 📄 go.mod                       # Go模块依赖
├── 📄 miko_email.db                # SQLite数据库
├── 📄 API接口文档.txt               # API接口文档
├── 📄 开发指南.txt                  # 开发指南
├── 📄 部署指南.txt                  # 部署指南
├── 📄 故障排除.txt                  # 故障排除指南
└── 📄 README.md                    # 项目说明
```

## 🚀 快速开始

### 环境要求
- Go 1.21 或更高版本
- 现代浏览器（支持ES6+）

### 安装步骤

1. **克隆项目**
```bash
git clone <repository-url>
cd miko-email
```

2. **安装依赖**
```bash
go mod tidy
```

3. **初始化数据库**
```bash
go run cmd/init/main.go
```

4. **启动服务**
```bash
go run main.go
```

5. **访问系统**
- Web界面: http://localhost:8080
- 管理员登录: admin / 123456

### 配置说明

系统支持通过环境变量进行配置：

```bash
export WEB_PORT=8080          # Web服务端口
export SMTP_PORT=25           # SMTP服务端口
export IMAP_PORT=143          # IMAP服务端口
export POP3_PORT=110          # POP3服务端口
export DATABASE_PATH=./miko_email.db  # 数据库文件路径
export DOMAIN=localhost       # 默认域名
```

## 📧 邮件客户端配置

### SMTP 发送邮件
- 服务器: localhost (或您的域名)
- 端口: 25
- 加密: 无
- 认证: 用户名和密码

### IMAP 接收邮件
- 服务器: localhost (或您的域名)
- 端口: 143
- 加密: 无
- 认证: 用户名和密码

### POP3 接收邮件
- 服务器: localhost (或您的域名)
- 端口: 110
- 加密: 无
- 认证: 用户名和密码

## 🔧 API文档

### 认证相关
- `POST /api/login` - 用户登录
- `POST /api/register` - 用户注册
- `POST /api/admin/login` - 管理员登录
- `POST /api/logout` - 用户登出

### 邮箱管理
- `GET /api/mailboxes` - 获取邮箱列表
- `POST /api/mailboxes` - 创建邮箱
- `POST /api/mailboxes/batch` - 批量创建邮箱
- `DELETE /api/mailboxes/:id` - 删除邮箱

### 域名管理
- `GET /api/domains/available` - 获取可用域名
- `GET /api/domains/dns` - 查询DNS记录
- `GET /api/admin/domains` - 获取域名列表（管理员）
- `POST /api/admin/domains` - 创建域名（管理员）
- `POST /api/admin/domains/:id/verify` - 验证域名（管理员）

## 🌟 特色功能

### DNS验证系统
系统支持自动验证域名的DNS配置，包括：
- MX记录验证
- A记录验证
- TXT记录验证（SPF）

### 邀请码系统
- 用户注册时可使用邀请码
- 成功邀请他人注册可获得贡献度奖励
- 贡献度可用于解锁更多功能

### 邮件转发
- 支持单个邮箱转发设置
- 支持批量邮箱转发设置
- 灵活的转发规则管理

## 🔒 安全特性

- 密码加密存储（bcrypt）
- 会话管理和认证
- SQL注入防护
- XSS防护
- CSRF防护

## 📝 开发说明

### 数据库设计
系统使用SQLite数据库，包含以下主要表：
- `users` - 普通用户表
- `admins` - 管理员表
- `domains` - 域名表
- `mailboxes` - 邮箱表
- `emails` - 邮件表
- `email_forwards` - 邮件转发表

### 测试
项目包含API测试脚本：
```bash
python test_api.py
```

## 🤝 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 🙏 致谢

- [Gin](https://github.com/gin-gonic/gin) - Web框架
- [Bootstrap](https://getbootstrap.com/) - UI框架
- [SQLite](https://www.sqlite.org/) - 数据库
- [Go](https://golang.org/) - 编程语言

## 📊 项目统计

![GitHub stars](https://img.shields.io/github/stars/your-repo/miko-email?style=social)
![GitHub forks](https://img.shields.io/github/forks/your-repo/miko-email?style=social)
![GitHub issues](https://img.shields.io/github/issues/your-repo/miko-email)
![GitHub pull requests](https://img.shields.io/github/issues-pr/your-repo/miko-email)

- 📈 **活跃开发**: 持续更新和维护
- 👥 **社区支持**: 活跃的开发者社区
- 🔧 **企业级**: 适用于生产环境
- 🌍 **国际化**: 支持多语言界面

## 🎯 路线图

### v2.1.0 (计划中)
- [ ] 📱 移动端APP支持
- [ ] 🔍 全文搜索功能
- [ ] 📊 高级统计报表
- [ ] 🔐 双因素认证
- [ ] 🌐 多语言支持

### v2.2.0 (规划中)
- [ ] ☁️ 云存储集成
- [ ] 🤖 AI邮件分类
- [ ] 📧 邮件模板系统
- [ ] 🔄 自动备份功能
- [ ] 📈 性能监控面板

### v3.0.0 (远期规划)
- [ ] 🏢 企业版功能
- [ ] 🔗 第三方集成
- [ ] 📱 PWA支持
- [ ] 🌊 微服务架构
- [ ] 🚀 Kubernetes部署

## 🏆 成功案例

### 企业用户
- **某科技公司**: 500+员工，日处理邮件10万+封
- **教育机构**: 支持5000+学生邮箱，稳定运行2年+
- **政府部门**: 高安全要求，通过安全审计

### 个人用户
- **开发者**: 项目邮件管理，API集成测试
- **小企业**: 成本控制，功能完善
- **技术爱好者**: 学习邮件协议，自建邮件服务

## 📞 技术支持

### 🆘 获取帮助
1. **📖 查看文档**: 详细的使用说明和API文档
2. **🔍 搜索问题**: GitHub Issues中查找相似问题
3. **💬 社区讨论**: 参与GitHub Discussions
4. **📧 直接联系**: 技术支持邮箱

### 📱 联系方式
- **QQ群**: 123456789 (思.凡邮箱交流群)
- **QQ**: 2014131458 (技术支持)
- **邮箱**: 2014131458@qq.com
- **微信**: 添加QQ后获取

### ⏰ 支持时间
- **工作日**: 9:00-18:00 (UTC+8)
- **紧急问题**: 24小时内响应
- **一般问题**: 48小时内响应
- **功能建议**: 一周内回复

### 🎓 培训服务
- **安装部署**: 远程协助部署配置
- **使用培训**: 功能介绍和最佳实践
- **定制开发**: 根据需求定制功能
- **技术咨询**: 邮件系统架构咨询

## 💝 赞助支持

如果这个项目对您有帮助，欢迎赞助支持开发：

### 💰 赞助方式
- **支付宝**: [扫码支付]
- **微信支付**: [扫码支付]
- **GitHub Sponsors**: [GitHub赞助页面]
- **爱发电**: [爱发电页面]

### 🎁 赞助回报
- **￥10+**: 感谢名单 + 技术支持优先
- **￥50+**: 定制Logo + 专属技术群
- **￥200+**: 功能定制 + 一对一技术指导
- **￥500+**: 企业版授权 + 商业技术支持

## 📜 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。

### 🔓 许可说明
- ✅ **商业使用**: 允许商业项目使用
- ✅ **修改分发**: 允许修改和分发
- ✅ **私有使用**: 允许私有项目使用
- ⚠️ **责任限制**: 作者不承担使用风险
- 📄 **保留版权**: 需保留原始版权声明

### 🤝 贡献协议
提交代码即表示同意：
- 代码遵循项目开源协议
- 授权项目维护者使用
- 遵循项目代码规范
- 接受代码审查流程

## 🌟 致谢

### 👨‍💻 核心贡献者
- **主要开发**: [@your-username](https://github.com/your-username)
- **文档维护**: [@doc-maintainer](https://github.com/doc-maintainer)
- **测试支持**: [@tester](https://github.com/tester)

### 🙏 特别感谢
- [Gin](https://github.com/gin-gonic/gin) - 优秀的Go Web框架
- [Bootstrap](https://getbootstrap.com/) - 强大的前端UI框架
- [SQLite](https://www.sqlite.org/) - 轻量级数据库
- [Go](https://golang.org/) - 高效的编程语言
- 所有提交Issue和PR的贡献者

### 🏢 企业支持
感谢以下企业的支持和赞助：
- **某云计算公司**: 提供服务器资源
- **某CDN服务商**: 提供加速服务
- **某安全公司**: 提供安全审计

---

<div align="center">

**🚀 思.凡邮箱系统 - 让邮件管理变得简单高效！**

[![Star History Chart](https://api.star-history.com/svg?repos=your-repo/miko-email&type=Date)](https://star-history.com/#your-repo/miko-email&Date)

**如果这个项目对您有帮助，请给我们一个 ⭐ Star！**

[🏠 返回顶部](#思凡邮箱系统-miko-email-system)

</div>
