package handlers

import (
	"net/http"
	"strconv"
	"time"

	"miko-email/internal/services/user"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

// UserResponse 用户响应结构体
type UserResponse struct {
	ID           int        `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	Status       string     `json:"status"`        // 转换后的状态字符串
	Contribution int        `json:"contribution"`
	InviteCode   string     `json:"invite_code"`
	InvitedBy    *int       `json:"invited_by"`
	MailboxCount int        `json:"mailbox_count"` // 邮箱数量
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLogin    *time.Time `json:"last_login"`
}

// convertUserToResponse 将用户模型转换为响应结构体
func convertUserToResponse(user *user.UserWithStats) *UserResponse {
	status := "suspended"
	if user.IsActive {
		status = "active"
	}

	return &UserResponse{
		ID:           user.ID,
		Username:     user.Username,
		Email:        user.Email,
		Status:       status,
		Contribution: user.Contribution,
		InviteCode:   user.InviteCode,
		InvitedBy:    user.InvitedBy,
		MailboxCount: user.MailboxCount,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		LastLogin:    nil, // TODO: 添加最后登录时间字段
	}
}

// convertUserWithStatsToResponse 将UserWithStats转换为响应结构体
func convertUserWithStatsToResponse(userStats user.UserWithStats) *UserResponse {
	status := "suspended"
	if userStats.IsActive {
		status = "active"
	}

	return &UserResponse{
		ID:           userStats.ID,
		Username:     userStats.Username,
		Email:        userStats.Email,
		Status:       status,
		Contribution: userStats.Contribution,
		InviteCode:   userStats.InviteCode,
		InvitedBy:    userStats.InvitedBy,
		MailboxCount: userStats.MailboxCount,
		CreatedAt:    userStats.CreatedAt,
		UpdatedAt:    userStats.UpdatedAt,
		LastLogin:    nil, // TODO: 添加最后登录时间字段
	}
}

type UserHandler struct {
	userService  *user.Service
	sessionStore *sessions.CookieStore
}

func NewUserHandler(userService *user.Service, sessionStore *sessions.CookieStore) *UserHandler {
	return &UserHandler{
		userService:  userService,
		sessionStore: sessionStore,
	}
}

// GetUsers 获取用户列表
func (h *UserHandler) GetUsers(c *gin.Context) {
	users, err := h.userService.GetUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取用户列表失败"})
		return
	}

	// 转换为响应结构体
	var userResponses []*UserResponse
	for _, userStats := range users {
		userResponses = append(userResponses, convertUserWithStatsToResponse(userStats))
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    userResponses,
	})
}

// GetUserByID 根据ID获取用户
func (h *UserHandler) GetUserByID(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "用户ID格式错误"})
		return
	}

	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    convertUserToResponse(user),
	})
}

// GetUserMailboxes 获取用户的邮箱列表
func (h *UserHandler) GetUserMailboxes(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "用户ID格式错误"})
		return
	}

	mailboxes, err := h.userService.GetUserMailboxes(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取用户邮箱失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    mailboxes,
	})
}

// UpdateUserStatus 更新用户状态
func (h *UserHandler) UpdateUserStatus(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "用户ID格式错误"})
		return
	}

	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	var isActive bool
	var message string

	switch req.Status {
	case "active":
		isActive = true
		message = "用户已启用"
	case "suspended":
		isActive = false
		message = "用户已暂停"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "无效的状态值"})
		return
	}

	err = h.userService.UpdateUserStatus(userID, isActive)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": message,
	})
}

// DeleteUser 删除用户
func (h *UserHandler) DeleteUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "用户ID格式错误"})
		return
	}

	err = h.userService.DeleteUser(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "用户删除成功",
	})
}
