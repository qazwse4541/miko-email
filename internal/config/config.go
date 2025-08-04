package config

import (
	"os"
)

type Config struct {
	WebPort         string
	SMTPPort        string
	SMTPPort587     string   // SMTP提交端口
	SMTPPort465     string   // SMTPS端口
	IMAPPort        string
	POP3Port        string
	DatabasePath    string
	SessionKey      string
	Domain          string
	EnableMultiSMTP bool     // 是否启用多SMTP端口
}

// GlobalYAMLConfig 全局YAML配置
var GlobalYAMLConfig *YAMLConfig

func Load() *Config {
	// 尝试加载YAML配置文件
	if yamlConfig, err := LoadYAMLConfig("config.yaml"); err == nil {
		GlobalYAMLConfig = yamlConfig
		return yamlConfig.ToConfig()
	}

	// 如果YAML配置文件不存在或加载失败，使用环境变量配置
	return &Config{
		WebPort:         getEnv("WEB_PORT", "8080"),
		SMTPPort:        getEnv("SMTP_PORT", "25"),
		SMTPPort587:     getEnv("SMTP_PORT_587", "587"),   // SMTP提交端口
		SMTPPort465:     getEnv("SMTP_PORT_465", "465"),   // SMTPS端口
		IMAPPort:        getEnv("IMAP_PORT", "143"),
		POP3Port:        getEnv("POP3_PORT", "110"),
		DatabasePath:    getEnv("DATABASE_PATH", "./miko_email.db"),
		SessionKey:      getEnv("SESSION_KEY", "miko-email-secret-key-change-in-production"),
		Domain:          getEnv("DOMAIN", "localhost"),
		EnableMultiSMTP: getEnvBool("ENABLE_MULTI_SMTP", true), // 默认启用多SMTP端口
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}

// GetSMTPPorts 获取所有SMTP端口
func (c *Config) GetSMTPPorts() []string {
	// 如果有YAML配置，优先使用YAML配置
	if GlobalYAMLConfig != nil {
		return GlobalYAMLConfig.GetSMTPPorts()
	}

	// 否则使用原有逻辑
	if c.EnableMultiSMTP {
		return []string{c.SMTPPort, c.SMTPPort587, c.SMTPPort465}
	}
	return []string{c.SMTPPort}
}

// GetAdminCredentials 获取管理员凭据
func GetAdminCredentials() (username, password, email string, enabled bool) {
	if GlobalYAMLConfig != nil {
		return GlobalYAMLConfig.GetAdminCredentials()
	}
	// 默认管理员凭据
	return getEnv("ADMIN_USERNAME", "admin"),
		   getEnv("ADMIN_PASSWORD", "admin123456"),
		   getEnv("ADMIN_EMAIL", "admin@localhost"),
		   getEnvBool("ADMIN_ENABLED", true)
}

// IsFeatureEnabled 检查功能是否启用
func IsFeatureEnabled(feature string) bool {
	if GlobalYAMLConfig != nil {
		return GlobalYAMLConfig.IsFeatureEnabled(feature)
	}
	// 默认功能开关
	switch feature {
	case "registration":
		return getEnvBool("ALLOW_REGISTRATION", true)
	case "search":
		return getEnvBool("ENABLE_SEARCH", true)
	case "attachments":
		return getEnvBool("ENABLE_ATTACHMENTS", true)
	case "spam_filter":
		return getEnvBool("ENABLE_SPAM_FILTER", false)
	case "forwarding":
		return getEnvBool("ENABLE_FORWARDING", true)
	default:
		return false
	}
}

// IsValidDomain 检查域名是否有效
func IsValidDomain(domain string) bool {
	if GlobalYAMLConfig != nil {
		return GlobalYAMLConfig.IsValidDomain(domain)
	}
	// 如果没有YAML配置，默认不限制域名
	return true
}

// IsDomainRestrictionEnabled 检查是否启用域名限制
func IsDomainRestrictionEnabled() bool {
	if GlobalYAMLConfig != nil {
		return GlobalYAMLConfig.IsDomainRestrictionEnabled()
	}
	// 默认不启用域名限制
	return getEnvBool("ENABLE_DOMAIN_RESTRICTION", false)
}

// GetSiteName 获取网站名称
func GetSiteName() string {
	if GlobalYAMLConfig != nil {
		return GlobalYAMLConfig.GetSiteName()
	}
	return getEnv("SITE_NAME", "Miko邮箱系统")
}

// GetSiteLogo 获取网站Logo
func GetSiteLogo() string {
	if GlobalYAMLConfig != nil {
		return GlobalYAMLConfig.GetSiteLogo()
	}
	return getEnv("SITE_LOGO", "/static/images/logo.png")
}

// GetCopyright 获取版权信息
func GetCopyright() string {
	if GlobalYAMLConfig != nil {
		return GlobalYAMLConfig.GetCopyright()
	}
	return getEnv("COPYRIGHT", "© 2024 Miko邮箱系统. All rights reserved.")
}

// IsMaintenanceMode 检查是否为维护模式
func IsMaintenanceMode() bool {
	if GlobalYAMLConfig != nil {
		return GlobalYAMLConfig.System.MaintenanceMode
	}
	return getEnvBool("MAINTENANCE_MODE", false)
}

// GetMaintenanceMessage 获取维护信息
func GetMaintenanceMessage() string {
	if GlobalYAMLConfig != nil {
		return GlobalYAMLConfig.System.MaintenanceMessage
	}
	return getEnv("MAINTENANCE_MESSAGE", "系统正在维护中，请稍后访问")
}
