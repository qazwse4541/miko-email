# Miko无限邮箱系统

<div align="center">

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.21-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

一个基于Go语言开发的完整邮箱系统，支持SMTP、IMAP、POP3协议，提供Web管理界面和无限邮箱创建功能。

[在线演示](http://111.119.198.162:8080) • [功能特性](#-功能特性) • [快速开始](#-快速开始) • [API文档](#-api文档) • [贡献指南](#-贡献指南)

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

### 核心功能
- ✅ **无限邮箱创建** - 用户可以创建无限数量的邮箱地址
- ✅ **多协议支持** - 支持SMTP(25)、IMAP(143)、POP3(110)协议
- ✅ **Web管理界面** - 现代化的Web界面，支持响应式设计
- ✅ **用户权限管理** - 区分普通用户和管理员权限
- ✅ **域名管理** - 支持多域名，DNS记录验证
- ✅ **邮件转发** - 支持邮件转发和批量操作

### 用户功能
- 用户注册/登录
- 邮箱创建和管理
- 邮件收发
- 邮件转发设置
- 密码修改
- 邀请码系统（贡献度奖励）

### 管理员功能
- 用户管理
- 域名管理和DNS验证
- 系统监控
- 邮箱分配

## 🌐 在线演示

> **演示地址**: [http://111.119.198.162:8080](http://111.119.198.162:8080)

**演示账号**:
- 管理员账号: `admin` / `123456`
- 普通用户: 可自行注册体验

> ⚠️ **注意**: 演示环境仅供功能体验，请勿存储重要数据

## 🛠️ 技术栈

### 后端
- **Go 1.21+** - 主要开发语言
- **Gin** - Web框架
- **SQLite** - 数据库（使用modernc.org/sqlite，无需CGO）
- **Gorilla Sessions** - 会话管理
- **DNS库** - DNS记录查询和验证

### 前端
- **HTML5 + CSS3** - 页面结构和样式
- **Bootstrap 5** - UI框架
- **JavaScript (ES6+)** - 交互逻辑
- **Axios** - HTTP请求库

### 邮件协议
- **SMTP** - 邮件发送协议
- **IMAP** - 邮件接收协议
- **POP3** - 邮件下载协议

## 📦 项目结构

```
miko-email/
├── cmd/
│   └── init/           # 数据库初始化工具
├── internal/
│   ├── config/         # 配置管理
│   ├── database/       # 数据库初始化
│   ├── handlers/       # HTTP处理器
│   ├── middleware/     # 中间件
│   ├── models/         # 数据模型
│   ├── server/         # 服务器配置
│   └── services/       # 业务逻辑服务
│       ├── auth/       # 认证服务
│       ├── domain/     # 域名服务
│       ├── email/      # 邮件服务
│       ├── forward/    # 转发服务
│       └── mailbox/    # 邮箱服务
├── scripts/            # 初始化脚本
├── web/
│   ├── static/         # 静态资源
│   │   ├── css/        # 样式文件
│   │   └── js/         # JavaScript文件
│   └── templates/      # HTML模板
├── main.go             # 主程序入口
├── go.mod              # Go模块文件
└── README.md           # 项目说明
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

## 📞 支持

如有问题或建议，请提交 Issue 或联系开发团队。

---

**Miko无限邮箱系统** - 让邮件管理变得简单高效！ 🚀
