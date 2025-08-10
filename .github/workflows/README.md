# GitHub Actions 工作流说明

本目录包含了 Miko Email 项目的 GitHub Actions 自动化工作流文件。

## 工作流文件

### 1. `build-release.yml` - 发布构建
**触发条件：**
- 推送标签时（如 `v1.0.0`）
- 手动触发

**功能：**
- 为多个平台构建二进制文件
- 创建 GitHub Release
- 上传构建产物到 Release

**支持平台：**
- Windows (amd64, 386, arm64)
- Linux (amd64, 386, arm64, arm)
- macOS (amd64, arm64)
- FreeBSD (amd64)

### 2. `build.yml` - 日常构建
**触发条件：**
- 推送到主分支
- Pull Request
- 手动触发

**功能：**
- 构建主要平台的二进制文件
- 运行测试
- 上传构建产物（保留7天）

## 使用方法

### 创建发布版本
1. 确保代码已提交并推送到主分支
2. 创建并推送标签：
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
3. GitHub Actions 会自动构建并创建 Release

### 手动触发构建
1. 进入 GitHub 仓库的 Actions 页面
2. 选择要运行的工作流
3. 点击 "Run workflow" 按钮

## 构建产物

### 文件命名规则
- Windows: `mikomail-windows-{arch}.exe`
- Linux: `mikomail-linux-{arch}`
- macOS: `mikomail-darwin-{arch}`
- FreeBSD: `mikomail-freebsd-{arch}`

### 架构说明
- `amd64`: 64位 x86 架构
- `386`: 32位 x86 架构
- `arm64`: 64位 ARM 架构
- `arm`: 32位 ARM 架构

## 配置说明

### 环境变量
- `CGO_ENABLED=0`: 禁用 CGO，生成静态链接的二进制文件
- `GOOS`: 目标操作系统
- `GOARCH`: 目标架构

### 构建标志
- `-ldflags="-s -w"`: 减小二进制文件大小
  - `-s`: 去除符号表
  - `-w`: 去除调试信息

## 注意事项

1. **Go 版本**: 当前使用 Go 1.21，可根据需要调整
2. **依赖缓存**: 使用 GitHub Actions 缓存加速构建
3. **权限**: Release 创建需要 `GITHUB_TOKEN` 权限
4. **文件权限**: Unix-like 系统的二进制文件会自动添加执行权限
5. **Actions 版本**: 使用最新版本的 GitHub Actions（v4/v5）避免弃用警告

## 故障排除

### 构建失败
1. 检查 Go 版本兼容性
2. 确认依赖项是否正确
3. 查看构建日志中的错误信息

### Release 创建失败
1. 确认标签格式正确（以 `v` 开头）
2. 检查 GitHub Token 权限
3. 确认仓库设置允许创建 Release

## 自定义配置

如需修改构建配置，可以编辑对应的 `.yml` 文件：
- 添加/删除目标平台
- 修改 Go 版本
- 调整构建参数
- 自定义 Release 说明
