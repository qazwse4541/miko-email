package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

type AuthMiddleware struct {
	sessionStore *sessions.CookieStore
}

func NewAuthMiddleware(sessionStore *sessions.CookieStore) *AuthMiddleware {
	return &AuthMiddleware{sessionStore: sessionStore}
}

// RequireAuth 要求用户登录
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := m.sessionStore.Get(c.Request, "miko-session")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "会话错误"})
			c.Abort()
			return
		}

		userID, ok := session.Values["user_id"]
		if !ok || userID == nil {
			if c.Request.Header.Get("Content-Type") == "application/json" {
				c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "请先登录"})
			} else {
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}

		// 将用户信息存储到上下文中
		c.Set("user_id", userID)
		c.Set("is_admin", session.Values["is_admin"])
		c.Set("username", session.Values["username"])

		c.Next()
	}
}

type AdminMiddleware struct {
	sessionStore *sessions.CookieStore
}

func NewAdminMiddleware(sessionStore *sessions.CookieStore) *AdminMiddleware {
	return &AdminMiddleware{sessionStore: sessionStore}
}

// RequireAdmin 要求管理员权限
func (m *AdminMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := m.sessionStore.Get(c.Request, "miko-session")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "会话错误"})
			c.Abort()
			return
		}

		userID, ok := session.Values["user_id"]
		if !ok || userID == nil {
			if c.Request.Header.Get("Content-Type") == "application/json" {
				c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "请先登录"})
			} else {
				c.Redirect(http.StatusFound, "/admin/login")
			}
			c.Abort()
			return
		}

		isAdmin, ok := session.Values["is_admin"]
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "需要管理员权限"})
			c.Abort()
			return
		}

		// 安全的类型断言
		adminBool, ok := isAdmin.(bool)
		if !ok || !adminBool {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "需要管理员权限"})
			c.Abort()
			return
		}

		// 将用户信息存储到上下文中
		c.Set("user_id", userID)
		c.Set("is_admin", true)
		c.Set("username", session.Values["username"])

		c.Next()
	}
}
