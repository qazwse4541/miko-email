package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// YAMLConfig YAML配置文件结构
type YAMLConfig struct {
	Server struct {
		WebPort int `yaml:"web_port"`
		SMTP    struct {
			EnableMultiPort bool `yaml:"enable_multi_port"`
			Port25          int  `yaml:"port_25"`
			Port587         int  `yaml:"port_587"`
			Port465         int  `yaml:"port_465"`
		} `yaml:"smtp"`
		IMAP struct {
			Port       int `yaml:"port"`
			SecurePort int `yaml:"secure_port"`
		} `yaml:"imap"`
		POP3 struct {
			Port       int `yaml:"port"`
			SecurePort int `yaml:"secure_port"`
		} `yaml:"pop3"`
	} `yaml:"server"`
	
	Admin struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Email    string `yaml:"email"`
		Enabled  bool   `yaml:"enabled"`
	} `yaml:"admin"`
	
	Database struct {
		Path  string `yaml:"path"`
		Debug bool   `yaml:"debug"`
	} `yaml:"database"`
	
	Domain struct {
		Default                 string   `yaml:"default"`
		SMTPHostname            string   `yaml:"smtp_hostname"`
		Allowed                 []string `yaml:"allowed"`
		EnableDomainRestriction bool     `yaml:"enable_domain_restriction"`
	} `yaml:"domain"`
	
	Security struct {
		SessionKey     string `yaml:"session_key"`
		JWTSecret      string `yaml:"jwt_secret"`
		SessionTimeout int    `yaml:"session_timeout"`
		EnableHTTPS    bool   `yaml:"enable_https"`
		SSLCert        string `yaml:"ssl_cert"`
		SSLKey         string `yaml:"ssl_key"`
	} `yaml:"security"`
	
	Email struct {
		MaxSize              int  `yaml:"max_size"`
		MaxMailboxesPerUser  int  `yaml:"max_mailboxes_per_user"`
		RetentionDays        int  `yaml:"retention_days"`
		EnableForwarding     bool `yaml:"enable_forwarding"`
	} `yaml:"email"`
	
	SMTPSender struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
		Secure   string `yaml:"secure"`
		FromName string `yaml:"from_name"`
	} `yaml:"smtp_sender"`
	
	Logging struct {
		Level     string `yaml:"level"`
		ToFile    bool   `yaml:"to_file"`
		FilePath  string `yaml:"file_path"`
		AccessLog bool   `yaml:"access_log"`
	} `yaml:"logging"`
	
	Performance struct {
		MaxConnections int `yaml:"max_connections"`
		ReadTimeout    int `yaml:"read_timeout"`
		WriteTimeout   int `yaml:"write_timeout"`
		IdleTimeout    int `yaml:"idle_timeout"`
	} `yaml:"performance"`
	
	Features struct {
		AllowRegistration   bool `yaml:"allow_registration"`
		EnableSearch        bool `yaml:"enable_search"`
		EnableAttachments   bool `yaml:"enable_attachments"`
		EnableSpamFilter    bool `yaml:"enable_spam_filter"`
	} `yaml:"features"`
	
	System struct {
		SiteName              string `yaml:"site_name"`
		SiteLogo              string `yaml:"site_logo"`
		SiteDescription       string `yaml:"site_description"`
		SiteKeywords          string `yaml:"site_keywords"`
		Copyright             string `yaml:"copyright"`
		ContactEmail          string `yaml:"contact_email"`
		AllowSelfRegistration bool   `yaml:"allow_self_registration"`
		DefaultMailboxQuota   int    `yaml:"default_mailbox_quota"`
		MaintenanceMode       bool   `yaml:"maintenance_mode"`
		MaintenanceMessage    string `yaml:"maintenance_message"`
	} `yaml:"system"`
}

// LoadYAMLConfig 加载YAML配置文件
func LoadYAMLConfig(configPath string) (*YAMLConfig, error) {
	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 读取配置文件
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析YAML
	var config YAMLConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析YAML配置失败: %v", err)
	}

	return &config, nil
}

// ToConfig 将YAML配置转换为原有的Config结构
func (yc *YAMLConfig) ToConfig() *Config {
	return &Config{
		WebPort:         strconv.Itoa(yc.Server.WebPort),
		SMTPPort:        strconv.Itoa(yc.Server.SMTP.Port25),
		SMTPPort587:     strconv.Itoa(yc.Server.SMTP.Port587),
		SMTPPort465:     strconv.Itoa(yc.Server.SMTP.Port465),
		IMAPPort:        strconv.Itoa(yc.Server.IMAP.Port),
		IMAPSecurePort:  strconv.Itoa(yc.Server.IMAP.SecurePort),
		POP3Port:        strconv.Itoa(yc.Server.POP3.Port),
		POP3SecurePort:  strconv.Itoa(yc.Server.POP3.SecurePort),
		DatabasePath:    yc.Database.Path,
		SessionKey:      yc.Security.SessionKey,
		Domain:          yc.Domain.Default,
		EnableMultiSMTP: yc.Server.SMTP.EnableMultiPort,
	}
}

// GetAdminCredentials 获取管理员凭据
func (yc *YAMLConfig) GetAdminCredentials() (username, password, email string, enabled bool) {
	return yc.Admin.Username, yc.Admin.Password, yc.Admin.Email, yc.Admin.Enabled
}

// GetSMTPPorts 获取SMTP端口列表
func (yc *YAMLConfig) GetSMTPPorts() []string {
	if yc.Server.SMTP.EnableMultiPort {
		return []string{
			strconv.Itoa(yc.Server.SMTP.Port25),
			strconv.Itoa(yc.Server.SMTP.Port587),
			strconv.Itoa(yc.Server.SMTP.Port465),
		}
	}
	return []string{strconv.Itoa(yc.Server.SMTP.Port25)}
}

// GetAllowedDomains 获取允许的域名列表
func (yc *YAMLConfig) GetAllowedDomains() []string {
	return yc.Domain.Allowed
}

// IsDomainRestrictionEnabled 检查是否启用域名限制
func (yc *YAMLConfig) IsDomainRestrictionEnabled() bool {
	return yc.Domain.EnableDomainRestriction
}

// IsValidDomain 检查域名是否有效（如果启用了域名限制）
func (yc *YAMLConfig) IsValidDomain(domain string) bool {
	// 如果没有启用域名限制，所有域名都有效
	if !yc.Domain.EnableDomainRestriction {
		return true
	}

	// 如果允许列表为空，表示不限制
	if len(yc.Domain.Allowed) == 0 {
		return true
	}

	// 检查域名是否在允许列表中
	for _, allowedDomain := range yc.Domain.Allowed {
		if domain == allowedDomain {
			return true
		}
	}

	return false
}

// IsFeatureEnabled 检查功能是否启用
func (yc *YAMLConfig) IsFeatureEnabled(feature string) bool {
	switch feature {
	case "registration":
		// 优先使用系统设置中的自助注册开关
		return yc.System.AllowSelfRegistration
	case "search":
		return yc.Features.EnableSearch
	case "attachments":
		return yc.Features.EnableAttachments
	case "spam_filter":
		return yc.Features.EnableSpamFilter
	case "forwarding":
		return yc.Email.EnableForwarding
	default:
		return false
	}
}

// GetLogLevel 获取日志级别
func (yc *YAMLConfig) GetLogLevel() string {
	return yc.Logging.Level
}

// IsHTTPSEnabled 检查是否启用HTTPS
func (yc *YAMLConfig) IsHTTPSEnabled() bool {
	return yc.Security.EnableHTTPS
}

// GetSSLConfig 获取SSL配置
func (yc *YAMLConfig) GetSSLConfig() (certFile, keyFile string) {
	return yc.Security.SSLCert, yc.Security.SSLKey
}

// GetSMTPSenderConfig 获取SMTP发送配置
func (yc *YAMLConfig) GetSMTPSenderConfig() (host string, port int, username, password, secure, fromName string) {
	return yc.SMTPSender.Host, yc.SMTPSender.Port, yc.SMTPSender.Username, 
		   yc.SMTPSender.Password, yc.SMTPSender.Secure, yc.SMTPSender.FromName
}

// GetSystemSettings 获取系统设置
func (yc *YAMLConfig) GetSystemSettings() map[string]interface{} {
	return map[string]interface{}{
		"site_name":                yc.System.SiteName,
		"site_logo":                yc.System.SiteLogo,
		"site_description":         yc.System.SiteDescription,
		"site_keywords":            yc.System.SiteKeywords,
		"copyright":                yc.System.Copyright,
		"contact_email":            yc.System.ContactEmail,
		"allow_self_registration":  yc.System.AllowSelfRegistration,
		"default_mailbox_quota":    yc.System.DefaultMailboxQuota,
		"maintenance_mode":         yc.System.MaintenanceMode,
		"maintenance_message":      yc.System.MaintenanceMessage,
	}
}

// GetSiteName 获取网站名称
func (yc *YAMLConfig) GetSiteName() string {
	if yc.System.SiteName != "" {
		return yc.System.SiteName
	}
	return "思.凡邮箱系统"
}

// GetSiteLogo 获取网站Logo
func (yc *YAMLConfig) GetSiteLogo() string {
	if yc.System.SiteLogo != "" {
		return yc.System.SiteLogo
	}
	return "/static/images/logo.png"
}

// GetCopyright 获取版权信息
func (yc *YAMLConfig) GetCopyright() string {
	if yc.System.Copyright != "" {
		return yc.System.Copyright
	}
	return "© 2024 思.凡邮箱系统. All rights reserved."
}
