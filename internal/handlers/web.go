package handlers

import (
	"net/http"

	"miko-email/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

type WebHandler struct {
	sessionStore *sessions.CookieStore
}

func NewWebHandler(sessionStore *sessions.CookieStore) *WebHandler {
	return &WebHandler{sessionStore: sessionStore}
}

// Home 首页
func (h *WebHandler) Home(c *gin.Context) {
	c.HTML(http.StatusOK, "home.html", gin.H{
		"title":     config.GetSiteName(),
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// LoginPage 登录页面
func (h *WebHandler) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title":              "用户登录",
		"site_name":          config.GetSiteName(),
		"site_logo":          config.GetSiteLogo(),
		"copyright":          config.GetCopyright(),
		"allow_registration": config.IsFeatureEnabled("registration"),
	})
}

// RegisterPage 注册页面
func (h *WebHandler) RegisterPage(c *gin.Context) {
	// 检查是否允许用户注册
	if !config.IsFeatureEnabled("registration") {
		c.HTML(http.StatusForbidden, "login.html", gin.H{
			"title":              "用户登录",
			"site_name":          config.GetSiteName(),
			"site_logo":          config.GetSiteLogo(),
			"copyright":          config.GetCopyright(),
			"error":              "用户注册功能已关闭，请联系管理员",
			"allow_registration": false,
		})
		return
	}

	c.HTML(http.StatusOK, "register.html", gin.H{
		"title":              "用户注册",
		"site_name":          config.GetSiteName(),
		"site_logo":          config.GetSiteLogo(),
		"copyright":          config.GetCopyright(),
		"allow_registration": true,
	})
}

// AdminLoginPage 管理员登录页面
func (h *WebHandler) AdminLoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin_login.html", gin.H{
		"title":     "管理员登录",
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// Dashboard 用户仪表板
func (h *WebHandler) Dashboard(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title":     "用户中心",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// ComposePage 写邮件页面
func (h *WebHandler) ComposePage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "compose.html", gin.H{
		"title":     "写邮件",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// ForwardPage 转邮件页面
func (h *WebHandler) ForwardPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "forward.html", gin.H{
		"title":     "转邮件",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// InboxPage 收件箱页面
func (h *WebHandler) InboxPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "inbox.html", gin.H{
		"title":     "收件箱",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// SentPage 已发送页面
func (h *WebHandler) SentPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "sent.html", gin.H{
		"title":     "已发送",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// SettingsPage 设置页面
func (h *WebHandler) SettingsPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "settings.html", gin.H{
		"title":     "设置",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// MailboxesPage 邮箱管理页面
func (h *WebHandler) MailboxesPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "mailboxes.html", gin.H{
		"title":     "邮箱管理",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// AdminDashboard 管理员仪表板
func (h *WebHandler) AdminDashboard(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "admin_dashboard.html", gin.H{
		"title":     "管理员中心",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// UsersPage 用户管理页面
func (h *WebHandler) UsersPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "admin_users.html", gin.H{
		"title":     "用户管理",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// DomainsPage 域名管理页面
func (h *WebHandler) DomainsPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "admin_domains.html", gin.H{
		"title":     "域名管理",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// AdminMailboxesPage 管理员邮箱管理页面
func (h *WebHandler) AdminMailboxesPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "admin_mailboxes.html", gin.H{
		"title":     "邮箱管理",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// ForgotPasswordPage 找回密码页面
func (h *WebHandler) ForgotPasswordPage(c *gin.Context) {
	c.HTML(http.StatusOK, "forgot_password.html", gin.H{
		"title":     "找回密码",
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}

// ResetPasswordPage 重置密码页面
func (h *WebHandler) ResetPasswordPage(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.HTML(http.StatusBadRequest, "forgot_password.html", gin.H{
			"title":     "找回密码",
			"site_name": config.GetSiteName(),
			"site_logo": config.GetSiteLogo(),
			"copyright": config.GetCopyright(),
			"error":     "无效的重置链接",
		})
		return
	}
	
	c.HTML(http.StatusOK, "reset_password.html", gin.H{
		"title":     "重置密码",
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
		"token":     token,
	})
}

// SystemSettingsPage 系统设置页面
func (h *WebHandler) SystemSettingsPage(c *gin.Context) {
	username := c.GetString("username")
	c.HTML(http.StatusOK, "admin_system_settings.html", gin.H{
		"title":     "系统设置",
		"username":  username,
		"site_name": config.GetSiteName(),
		"site_logo": config.GetSiteLogo(),
		"copyright": config.GetCopyright(),
	})
}
