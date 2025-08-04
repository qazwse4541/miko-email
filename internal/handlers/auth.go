package handlers

import (
	"database/sql"
	"fmt"
	"net/http"

	"miko-email/internal/config"
	"miko-email/internal/models"
	"miko-email/internal/services/auth"
	"miko-email/internal/services/mail"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

type AuthHandler struct {
	authService  *auth.Service
	sessionStore *sessions.CookieStore
	db           *sql.DB
	mailService  *mail.Service
}

func NewAuthHandler(authService *auth.Service, sessionStore *sessions.CookieStore, db *sql.DB, mailService *mail.Service) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		sessionStore: sessionStore,
		db:           db,
		mailService:  mailService,
	}
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Username     string `json:"username" binding:"required"`
	Password     string `json:"password" binding:"required"`
	Email        string `json:"email" binding:"required,email"`
	DomainPrefix string `json:"domain_prefix" binding:"required"`
	DomainID     int    `json:"domain_id" binding:"required"`
	InviteCode   string `json:"invite_code"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login 用户登录
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	user, err := h.authService.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": err.Error()})
		return
	}

	// 创建会话
	session, err := h.sessionStore.Get(c.Request, "miko-session")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "会话创建失败"})
		return
	}

	session.Values["user_id"] = user.ID
	session.Values["username"] = user.Username
	session.Values["is_admin"] = false

	if err := session.Save(c.Request, c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "会话保存失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "登录成功",
		"data": gin.H{
			"user": gin.H{
				"id":           user.ID,
				"username":     user.Username,
				"email":        user.Email,
				"contribution": user.Contribution,
				"is_admin":     false,
			},
		},
	})
}

// AdminLogin 管理员登录
func (h *AuthHandler) AdminLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	admin, err := h.authService.AuthenticateAdmin(req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": err.Error()})
		return
	}

	// 创建会话
	session, err := h.sessionStore.Get(c.Request, "miko-session")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "会话创建失败"})
		return
	}

	session.Values["user_id"] = admin.ID
	session.Values["username"] = admin.Username
	session.Values["is_admin"] = true

	if err := session.Save(c.Request, c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "会话保存失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "登录成功",
		"data": gin.H{
			"user": gin.H{
				"id":           admin.ID,
				"username":     admin.Username,
				"email":        admin.Email,
				"contribution": admin.Contribution,
				"is_admin":     true,
			},
		},
	})
}

// Register 用户注册
func (h *AuthHandler) Register(c *gin.Context) {
	// 检查是否允许用户注册
	if !config.IsFeatureEnabled("registration") {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "用户注册功能已关闭"})
		return
	}

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	user, err := h.authService.RegisterUser(req.Username, req.Password, req.Email, req.DomainPrefix, req.DomainID, req.InviteCode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "注册成功",
		"data": gin.H{
			"user": gin.H{
				"id":           user.ID,
				"username":     user.Username,
				"email":        user.Email,
				"contribution": user.Contribution,
				"invite_code":  user.InviteCode,
			},
		},
	})
}

// Logout 用户登出
func (h *AuthHandler) Logout(c *gin.Context) {
	session, err := h.sessionStore.Get(c.Request, "miko-session")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "会话错误"})
		return
	}

	// 清除会话
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1

	if err := session.Save(c.Request, c.Writer); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "登出失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "登出成功"})
}

// GetProfile 获取用户信息
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")

	if isAdmin {
		// 管理员用户
		var admin models.Admin
		query := `
			SELECT id, username, email, contribution, invite_code, created_at, updated_at
			FROM admins
			WHERE id = ?
		`

		err := h.db.QueryRow(query, userID).Scan(
			&admin.ID, &admin.Username, &admin.Email,
			&admin.Contribution, &admin.InviteCode,
			&admin.CreatedAt, &admin.UpdatedAt,
		)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取用户信息失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"id":           admin.ID,
				"username":     admin.Username,
				"email":        admin.Email,
				"contribution": admin.Contribution,
				"invite_code":  admin.InviteCode,
				"is_admin":     true,
				"created_at":   admin.CreatedAt,
			},
		})
	} else {
		// 普通用户
		var user models.User
		query := `
			SELECT id, username, email, contribution, invite_code, invited_by, created_at, updated_at
			FROM users
			WHERE id = ?
		`

		err := h.db.QueryRow(query, userID).Scan(
			&user.ID, &user.Username, &user.Email,
			&user.Contribution, &user.InviteCode, &user.InvitedBy,
			&user.CreatedAt, &user.UpdatedAt,
		)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取用户信息失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"id":           user.ID,
				"username":     user.Username,
				"email":        user.Email,
				"contribution": user.Contribution,
				"invite_code":  user.InviteCode,
				"invited_by":   user.InvitedBy,
				"is_admin":     false,
				"created_at":   user.CreatedAt,
			},
		})
	}
}

// ChangePassword 修改密码
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")

	err := h.authService.ChangePassword(userID, req.OldPassword, req.NewPassword, isAdmin)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "密码修改成功"})
}

// ForgotPassword 找回密码
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	// 生成重置令牌
	token, err := h.authService.GenerateResetToken(req.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	// 获取用户信息
	user, err := h.authService.GetUserByEmail(req.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	// 构建重置链接
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", getBaseURL(c), token)

	// 检查邮件服务是否可用
	if h.mailService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "邮件服务未配置，请联系管理员"})
		return
	}

	// 发送重置邮件
	err = h.mailService.SendPasswordResetEmail(req.Email, user.Username, resetURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": fmt.Sprintf("邮件发送失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "重置密码邮件已发送，请检查您的邮箱",
	})
}

// ResetPassword 重置密码
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	// 验证密码长度
	if len(req.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "密码长度至少6位"})
		return
	}

	// 重置密码
	err := h.authService.ResetPassword(req.Token, req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "密码重置成功",
	})
}

// getBaseURL 获取基础URL
func getBaseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, c.Request.Host)
}
