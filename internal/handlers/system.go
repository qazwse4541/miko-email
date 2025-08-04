package handlers

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"time"

	"miko-email/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type SystemHandler struct {
	sessionStore *sessions.CookieStore
	db           *sql.DB
}

func NewSystemHandler(sessionStore *sessions.CookieStore, db *sql.DB) *SystemHandler {
	return &SystemHandler{
		sessionStore: sessionStore,
		db:           db,
	}
}

type SystemSettingsRequest struct {
	SiteName              string `json:"site_name" binding:"required"`
	SiteLogo              string `json:"site_logo"`
	SiteDescription       string `json:"site_description"`
	SiteKeywords          string `json:"site_keywords"`
	Copyright             string `json:"copyright"`
	ContactEmail          string `json:"contact_email"`
	AllowSelfRegistration bool   `json:"allow_self_registration"`
	DefaultMailboxQuota   int    `json:"default_mailbox_quota"`
	MaintenanceMode       bool   `json:"maintenance_mode"`
	MaintenanceMessage    string `json:"maintenance_message"`
}

type AdminPasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

type SMTPSettingsRequest struct {
	Host     string `json:"host" binding:"required"`
	Port     int    `json:"port" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Secure   string `json:"secure" binding:"required"`
	FromName string `json:"from_name" binding:"required"`
}

// GetSystemSettings 获取系统设置
func (h *SystemHandler) GetSystemSettings(c *gin.Context) {
	if config.GlobalYAMLConfig == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "配置文件未加载"})
		return
	}

	settings := config.GlobalYAMLConfig.GetSystemSettings()
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    settings,
	})
}

// UpdateSystemSettings 更新系统设置
func (h *SystemHandler) UpdateSystemSettings(c *gin.Context) {
	var req SystemSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	if config.GlobalYAMLConfig == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "配置文件未加载"})
		return
	}

	// 更新配置
	config.GlobalYAMLConfig.System.SiteName = req.SiteName
	config.GlobalYAMLConfig.System.SiteLogo = req.SiteLogo
	config.GlobalYAMLConfig.System.SiteDescription = req.SiteDescription
	config.GlobalYAMLConfig.System.SiteKeywords = req.SiteKeywords
	config.GlobalYAMLConfig.System.Copyright = req.Copyright
	config.GlobalYAMLConfig.System.ContactEmail = req.ContactEmail
	config.GlobalYAMLConfig.System.AllowSelfRegistration = req.AllowSelfRegistration
	config.GlobalYAMLConfig.System.DefaultMailboxQuota = req.DefaultMailboxQuota
	config.GlobalYAMLConfig.System.MaintenanceMode = req.MaintenanceMode
	config.GlobalYAMLConfig.System.MaintenanceMessage = req.MaintenanceMessage
	
	// 同时更新features中的注册开关，保持一致性
	config.GlobalYAMLConfig.Features.AllowRegistration = req.AllowSelfRegistration

	// 保存配置到文件
	if err := h.saveConfigToFile(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "保存配置失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "系统设置更新成功",
	})
}

// GetAdminSettings 获取管理员设置
func (h *SystemHandler) GetAdminSettings(c *gin.Context) {
	if config.GlobalYAMLConfig == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "配置文件未加载"})
		return
	}

	username, _, email, enabled := config.GlobalYAMLConfig.GetAdminCredentials()
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"username": username,
			"email":    email,
			"enabled":  enabled,
		},
	})
}

// UpdateAdminPassword 更新管理员密码
func (h *SystemHandler) UpdateAdminPassword(c *gin.Context) {
	var req AdminPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	if req.NewPassword != req.ConfirmPassword {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "新密码和确认密码不一致"})
		return
	}

	if len(req.NewPassword) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "密码长度至少6位"})
		return
	}

	if config.GlobalYAMLConfig == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "配置文件未加载"})
		return
	}

	// 验证当前密码
	_, currentPassword, _, _ := config.GlobalYAMLConfig.GetAdminCredentials()
	if currentPassword != req.CurrentPassword {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "当前密码错误"})
		return
	}

	// 更新配置文件中的密码
	config.GlobalYAMLConfig.Admin.Password = req.NewPassword

	// 同时更新数据库中的管理员密码
	if err := h.updateAdminPasswordInDatabase(req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "更新数据库密码失败: " + err.Error()})
		return
	}

	// 保存配置到文件
	if err := h.saveConfigToFile(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "保存配置失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "管理员密码更新成功",
	})
}

// GetSMTPSettings 获取SMTP设置
func (h *SystemHandler) GetSMTPSettings(c *gin.Context) {
	if config.GlobalYAMLConfig == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "配置文件未加载"})
		return
	}

	host, port, username, password, secure, fromName := config.GlobalYAMLConfig.GetSMTPSenderConfig()
	
	// 隐藏密码
	maskedPassword := ""
	if len(password) > 0 {
		maskedPassword = "********"
	}
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"host":      host,
			"port":      port,
			"username":  username,
			"password":  maskedPassword,
			"secure":    secure,
			"from_name": fromName,
		},
	})
}

// UpdateSMTPSettings 更新SMTP设置
func (h *SystemHandler) UpdateSMTPSettings(c *gin.Context) {
	var req SMTPSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	if config.GlobalYAMLConfig == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "配置文件未加载"})
		return
	}

	// 更新SMTP配置
	config.GlobalYAMLConfig.SMTPSender.Host = req.Host
	config.GlobalYAMLConfig.SMTPSender.Port = req.Port
	config.GlobalYAMLConfig.SMTPSender.Username = req.Username
	// 如果密码不是掩码，则更新密码
	if req.Password != "********" {
		config.GlobalYAMLConfig.SMTPSender.Password = req.Password
	}
	config.GlobalYAMLConfig.SMTPSender.Secure = req.Secure
	config.GlobalYAMLConfig.SMTPSender.FromName = req.FromName

	// 保存配置到文件
	if err := h.saveConfigToFile(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "保存配置失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "SMTP设置更新成功",
	})
}

// TestSMTPSettings 测试SMTP设置
func (h *SystemHandler) TestSMTPSettings(c *gin.Context) {
	var req SMTPSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	// 如果密码是掩码，使用配置文件中的真实密码
	if req.Password == "********" {
		if config.GlobalYAMLConfig != nil {
			_, _, _, realPassword, _, _ := config.GlobalYAMLConfig.GetSMTPSenderConfig()
			req.Password = realPassword
		}
	}

	// 实现SMTP连接测试
	if err := h.testSMTPConnection(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "SMTP连接测试失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "SMTP连接测试成功",
	})
}

// UploadLogo 上传网站Logo
func (h *SystemHandler) UploadLogo(c *gin.Context) {
	file, err := c.FormFile("logo")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "上传文件失败"})
		return
	}

	// 检查文件类型
	if !isImageFile(file.Filename) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "只支持图片文件"})
		return
	}

	// 检查文件大小 (最大2MB)
	if file.Size > 2*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "文件大小不能超过2MB"})
		return
	}

	// 创建上传目录
	uploadDir := "./web/static/images"
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "创建上传目录失败"})
		return
	}

	// 生成文件名
	filename := "logo" + filepath.Ext(file.Filename)
	filepath := filepath.Join(uploadDir, filename)

	// 保存文件
	if err := c.SaveUploadedFile(file, filepath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "保存文件失败"})
		return
	}

	// 返回文件路径
	logoPath := "/static/images/" + filename
	
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Logo上传成功",
		"data": gin.H{
			"logo_path": logoPath,
		},
	})
}

// saveConfigToFile 保存配置到文件
func (h *SystemHandler) saveConfigToFile() error {
	data, err := yaml.Marshal(config.GlobalYAMLConfig)
	if err != nil {
		return err
	}

	return os.WriteFile("config.yaml", data, 0644)
}

// updateAdminPasswordInDatabase 更新数据库中的管理员密码
func (h *SystemHandler) updateAdminPasswordInDatabase(newPassword string) error {
	if h.db == nil {
		return fmt.Errorf("数据库连接未初始化")
	}

	// 获取管理员用户名
	username, _, _, _ := config.GlobalYAMLConfig.GetAdminCredentials()
	
	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("密码加密失败: %v", err)
	}

	// 更新数据库中的管理员密码
	_, err = h.db.Exec(`
		UPDATE admins 
		SET password = ?, updated_at = ? 
		WHERE username = ?
	`, string(hashedPassword), time.Now(), username)
	
	if err != nil {
		return fmt.Errorf("更新数据库密码失败: %v", err)
	}

	return nil
}

// isImageFile 检查是否为图片文件
func isImageFile(filename string) bool {
	ext := filepath.Ext(filename)
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp":
		return true
	default:
		return false
	}
}

// testSMTPConnection 测试SMTP连接
func (h *SystemHandler) testSMTPConnection(req SMTPSettingsRequest) error {
	// 验证必需字段
	if req.Host == "" {
		return fmt.Errorf("SMTP主机地址不能为空")
	}
	if req.Port <= 0 || req.Port > 65535 {
		return fmt.Errorf("SMTP端口无效")
	}
	if req.Username == "" {
		return fmt.Errorf("SMTP用户名不能为空")
	}
	if req.Password == "" || req.Password == "********" {
		return fmt.Errorf("SMTP密码不能为空")
	}

	// 构建服务器地址
	addr := fmt.Sprintf("%s:%d", req.Host, req.Port)

	// 根据安全类型选择连接方式
	var conn net.Conn
	var err error

	if req.Secure == "ssl" {
		// SSL/TLS连接
		tlsConfig := &tls.Config{
			ServerName: req.Host,
			InsecureSkipVerify: false, // 在生产环境中应该验证证书
		}
		conn, err = tls.Dial("tcp", addr, tlsConfig)
	} else {
		// 普通TCP连接
		conn, err = net.Dial("tcp", addr)
	}

	if err != nil {
		return fmt.Errorf("无法连接到SMTP服务器: %v", err)
	}
	defer conn.Close()

	// 创建SMTP客户端
	client, err := smtp.NewClient(conn, req.Host)
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %v", err)
	}
	defer client.Quit()

	// 如果是STARTTLS，升级连接
	if req.Secure == "tls" {
		tlsConfig := &tls.Config{
			ServerName: req.Host,
			InsecureSkipVerify: false,
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS失败: %v", err)
		}
	}

	// 尝试认证
	auth := smtp.PlainAuth("", req.Username, req.Password, req.Host)
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP认证失败: %v", err)
	}

	return nil
}