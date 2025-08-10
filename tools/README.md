# 工具使用说明

## 配置管理工具
```bash
# 查看管理员账号密码配置
go run tools/config_manager/main.go admin

# 显示当前配置
go run tools/config_manager/main.go show

# 测试配置文件
go run tools/config_manager/main.go test
```

## 管理员同步工具
```bash
# 同步管理员信息到数据库
go run tools/sync_admin/main.go sync

# 显示当前管理员信息
go run tools/sync_admin/main.go show

# 重置管理员密码
go run tools/sync_admin/main.go reset
```

## 编译工具
```bash
# 编译配置管理工具
go build -o config_manager tools/config_manager/main.go

# 编译管理员同步工具
go build -o sync_admin tools/sync_admin/main.go
```