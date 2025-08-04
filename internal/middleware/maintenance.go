package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"miko-email/internal/config"
)

type MaintenanceMiddleware struct {
	sessionStore *sessions.CookieStore
}

func NewMaintenanceMiddleware(sessionStore *sessions.CookieStore) *MaintenanceMiddleware {
	return &MaintenanceMiddleware{sessionStore: sessionStore}
}

// CheckMaintenance 检查维护模式
func (m *MaintenanceMiddleware) CheckMaintenance() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查是否启用维护模式
		if config.GlobalYAMLConfig == nil || !config.GlobalYAMLConfig.System.MaintenanceMode {
			c.Next()
			return
		}

		// 获取当前路径
		path := c.Request.URL.Path

		// 允许管理员相关路径访问
		if strings.HasPrefix(path, "/admin/") || strings.HasPrefix(path, "/api/admin/") {
			c.Next()
			return
		}

		// 允许登录和注销相关路径
		if path == "/login" || path == "/api/login" || path == "/api/logout" || 
		   path == "/admin/login" || path == "/api/admin/login" {
			c.Next()
			return
		}

		// 允许静态资源访问
		if strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/assets/") {
			c.Next()
			return
		}

		// 检查用户是否为管理员
		session, err := m.sessionStore.Get(c.Request, "miko-session")
		if err == nil {
			if isAdmin, ok := session.Values["is_admin"]; ok {
				if adminBool, ok := isAdmin.(bool); ok && adminBool {
					// 管理员可以继续访问
					c.Next()
					return
				}
			}
		}

		// 获取维护信息
		maintenanceMessage := config.GlobalYAMLConfig.System.MaintenanceMessage
		if maintenanceMessage == "" {
			maintenanceMessage = "系统正在维护中，请稍后访问"
		}

		// 对于API请求，返回JSON响应
		if strings.HasPrefix(path, "/api/") {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"success": false,
				"message": maintenanceMessage,
				"maintenance": true,
			})
			c.Abort()
			return
		}

		// 对于页面请求，显示维护页面
		c.HTML(http.StatusServiceUnavailable, "maintenance.html", gin.H{
			"title":     "系统维护",
			"site_name": config.GetSiteName(),
			"site_logo": config.GetSiteLogo(),
			"copyright": config.GetCopyright(),
			"message":   maintenanceMessage,
		})
		c.Abort()
	}
}
