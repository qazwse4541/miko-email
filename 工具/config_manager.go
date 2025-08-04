package main

import (
	"fmt"
	"os"

	"miko-email/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		showUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "show":
		showConfig()
	case "test":
		testConfig()
	case "admin":
		showAdminInfo()
	case "ports":
		showPorts()
	case "features":
		showFeatures()
	default:
		fmt.Printf("未知命令: %s\n", command)
		showUsage()
	}
}

func showUsage() {
	fmt.Println("Miko邮箱配置管理工具")
	fmt.Println("")
	fmt.Println("用法:")
	fmt.Println("  go run tools/config_manager.go <命令>")
	fmt.Println("")
	fmt.Println("命令:")
	fmt.Println("  show     - 显示当前配置")
	fmt.Println("  test     - 测试配置文件")
	fmt.Println("  admin    - 显示管理员信息")
	fmt.Println("  ports    - 显示端口配置")
	fmt.Println("  features - 显示功能开关")
	fmt.Println("")
	fmt.Println("示例:")
	fmt.Println("  go run tools/config_manager.go show")
	fmt.Println("  go run tools/config_manager.go admin")
}

func showConfig() {
	fmt.Println("=== Miko邮箱系统配置 ===")
	fmt.Println("")

	// 加载配置
	cfg := config.Load()

	// 检查是否使用YAML配置
	if config.GlobalYAMLConfig != nil {
		fmt.Println("✅ 使用YAML配置文件: config.yaml")
		fmt.Println("")
		
		yamlCfg := config.GlobalYAMLConfig
		
		fmt.Println("📡 服务器配置:")
		fmt.Printf("  Web端口: %d\n", yamlCfg.Server.WebPort)
		fmt.Printf("  多SMTP端口: %v\n", yamlCfg.Server.SMTP.EnableMultiPort)
		fmt.Printf("  SMTP端口: %d, %d, %d\n", 
			yamlCfg.Server.SMTP.Port25,
			yamlCfg.Server.SMTP.Port587,
			yamlCfg.Server.SMTP.Port465)
		fmt.Printf("  IMAP端口: %d\n", yamlCfg.Server.IMAP.Port)
		fmt.Printf("  POP3端口: %d\n", yamlCfg.Server.POP3.Port)
		fmt.Println("")
		
		fmt.Println("👤 管理员配置:")
		username, password, email, enabled := yamlCfg.GetAdminCredentials()
		fmt.Printf("  用户名: %s\n", username)
		fmt.Printf("  密码: %s\n", maskPassword(password))
		fmt.Printf("  邮箱: %s\n", email)
		fmt.Printf("  启用: %v\n", enabled)
		fmt.Println("")
		
		fmt.Println("💾 数据库配置:")
		fmt.Printf("  路径: %s\n", yamlCfg.Database.Path)
		fmt.Printf("  调试: %v\n", yamlCfg.Database.Debug)
		fmt.Println("")
		
		fmt.Println("🌐 域名配置:")
		fmt.Printf("  默认域名: %s\n", yamlCfg.Domain.Default)
		fmt.Printf("  域名限制: %v\n", yamlCfg.Domain.EnableDomainRestriction)
		if yamlCfg.Domain.EnableDomainRestriction && len(yamlCfg.Domain.Allowed) > 0 {
			fmt.Printf("  允许域名: %v\n", yamlCfg.Domain.Allowed)
		} else {
			fmt.Printf("  允许域名: 不限制 (接受所有域名)\n")
		}
		fmt.Println("")
		
	} else {
		fmt.Println("⚠️  使用环境变量配置 (未找到config.yaml)")
		fmt.Println("")
		
		fmt.Println("📡 服务器配置:")
		fmt.Printf("  Web端口: %s\n", cfg.WebPort)
		fmt.Printf("  SMTP端口: %s, %s, %s\n", cfg.SMTPPort, cfg.SMTPPort587, cfg.SMTPPort465)
		fmt.Printf("  IMAP端口: %s\n", cfg.IMAPPort)
		fmt.Printf("  POP3端口: %s\n", cfg.POP3Port)
		fmt.Printf("  多SMTP端口: %v\n", cfg.EnableMultiSMTP)
		fmt.Println("")
		
		fmt.Println("💾 数据库配置:")
		fmt.Printf("  路径: %s\n", cfg.DatabasePath)
		fmt.Println("")
		
		fmt.Println("🔐 安全配置:")
		fmt.Printf("  Session密钥: %s\n", maskPassword(cfg.SessionKey))
		fmt.Printf("  域名: %s\n", cfg.Domain)
		fmt.Println("")
	}
}

func testConfig() {
	fmt.Println("=== 配置文件测试 ===")
	fmt.Println("")

	// 尝试加载YAML配置
	yamlConfig, err := config.LoadYAMLConfig("config.yaml")
	if err != nil {
		fmt.Printf("❌ YAML配置加载失败: %v\n", err)
		fmt.Println("💡 请检查config.yaml文件是否存在且格式正确")
		return
	}

	fmt.Println("✅ YAML配置文件加载成功")
	fmt.Println("")

	// 验证配置
	fmt.Println("🔍 配置验证:")
	
	// 检查端口配置
	if yamlConfig.Server.WebPort <= 0 || yamlConfig.Server.WebPort > 65535 {
		fmt.Printf("❌ Web端口配置无效: %d\n", yamlConfig.Server.WebPort)
	} else {
		fmt.Printf("✅ Web端口: %d\n", yamlConfig.Server.WebPort)
	}
	
	// 检查SMTP端口
	smtpPorts := yamlConfig.GetSMTPPorts()
	fmt.Printf("✅ SMTP端口: %v\n", smtpPorts)
	
	// 检查管理员配置
	username, password, email, enabled := yamlConfig.GetAdminCredentials()
	if username == "" || password == "" {
		fmt.Println("❌ 管理员用户名或密码为空")
	} else {
		fmt.Printf("✅ 管理员配置: %s (%s) - 启用: %v\n", username, email, enabled)
	}
	
	// 检查数据库路径
	if yamlConfig.Database.Path == "" {
		fmt.Println("❌ 数据库路径为空")
	} else {
		fmt.Printf("✅ 数据库路径: %s\n", yamlConfig.Database.Path)
	}
	
	fmt.Println("")
	fmt.Println("🎉 配置文件测试完成")
}

func showAdminInfo() {
	fmt.Println("=== 管理员信息 ===")
	fmt.Println("")

	// 重新加载配置以获取最新信息
	config.GlobalYAMLConfig = nil
	config.Load()

	username, password, email, enabled := config.GetAdminCredentials()
	
	fmt.Printf("👤 用户名: %s\n", username)
	fmt.Printf("🔑 密码: %s\n", password)
	fmt.Printf("📧 邮箱: %s\n", email)
	fmt.Printf("✅ 启用: %v\n", enabled)
	fmt.Println("")
	
	if enabled {
		fmt.Println("🌐 管理员登录地址:")
		fmt.Println("   http://localhost:8080/admin/login")
		fmt.Println("")
		fmt.Println("💡 使用上述用户名和密码登录管理后台")
	} else {
		fmt.Println("⚠️  管理员账号已禁用")
	}
}

func showPorts() {
	fmt.Println("=== 端口配置 ===")
	fmt.Println("")

	cfg := config.Load()
	smtpPorts := cfg.GetSMTPPorts()

	fmt.Println("📡 服务端口:")
	fmt.Printf("  Web管理界面: %s\n", cfg.WebPort)
	fmt.Printf("  SMTP端口: %v\n", smtpPorts)
	fmt.Printf("  IMAP端口: %s\n", cfg.IMAPPort)
	fmt.Printf("  POP3端口: %s\n", cfg.POP3Port)
	fmt.Println("")
	
	fmt.Println("📝 端口说明:")
	fmt.Println("  25  - 标准SMTP端口")
	fmt.Println("  587 - SMTP提交端口 (推荐用于客户端发送)")
	fmt.Println("  465 - SMTPS安全端口 (SSL/TLS)")
	fmt.Println("  143 - IMAP端口")
	fmt.Println("  110 - POP3端口")
}

func showFeatures() {
	fmt.Println("=== 功能开关 ===")
	fmt.Println("")

	features := []string{"registration", "search", "attachments", "spam_filter", "forwarding"}
	
	for _, feature := range features {
		enabled := config.IsFeatureEnabled(feature)
		status := "❌"
		if enabled {
			status = "✅"
		}
		fmt.Printf("  %s %s\n", status, getFeatureName(feature))
	}
	fmt.Println("")
}

func maskPassword(password string) string {
	if len(password) <= 4 {
		return "****"
	}
	return password[:2] + "****" + password[len(password)-2:]
}

func getFeatureName(feature string) string {
	switch feature {
	case "registration":
		return "用户注册"
	case "search":
		return "邮件搜索"
	case "attachments":
		return "邮件附件"
	case "spam_filter":
		return "垃圾邮件过滤"
	case "forwarding":
		return "邮件转发"
	default:
		return feature
	}
}
