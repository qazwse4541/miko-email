package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"miko-email/internal/services/mailbox"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

type MailboxHandler struct {
	mailboxService *mailbox.Service
	sessionStore   *sessions.CookieStore
}

func NewMailboxHandler(mailboxService *mailbox.Service, sessionStore *sessions.CookieStore) *MailboxHandler {
	return &MailboxHandler{
		mailboxService: mailboxService,
		sessionStore:   sessionStore,
	}
}

type CreateMailboxRequest struct {
	Prefix   string `json:"prefix" binding:"required"`
	DomainID int    `json:"domain_id" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type BatchCreateMailboxRequest struct {
	Prefixes []string `json:"prefixes" binding:"required"`
	DomainID int      `json:"domain_id" binding:"required"`
}

// GetMailboxes 获取邮箱列表
func (h *MailboxHandler) GetMailboxes(c *gin.Context) {
	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")

	mailboxes, err := h.mailboxService.GetUserMailboxes(userID, isAdmin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取邮箱列表失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    mailboxes,
	})
}

// CreateMailbox 创建邮箱
func (h *MailboxHandler) CreateMailbox(c *gin.Context) {
	var req CreateMailboxRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")

	// 验证前缀格式
	if !isValidEmailPrefix(req.Prefix) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮箱前缀格式不正确"})
		return
	}

	if len(req.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "密码长度至少6位"})
		return
	}

	mailbox, err := h.mailboxService.CreateMailboxWithPassword(userID, req.Prefix, req.Password, req.DomainID, isAdmin)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "邮箱创建成功",
		"data":    mailbox,
	})
}

// BatchCreateMailboxes 批量创建邮箱
func (h *MailboxHandler) BatchCreateMailboxes(c *gin.Context) {
	var req BatchCreateMailboxRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")

	// 验证所有前缀格式
	for _, prefix := range req.Prefixes {
		if !isValidEmailPrefix(prefix) {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮箱前缀格式不正确: " + prefix})
			return
		}
	}

	mailboxes, err := h.mailboxService.BatchCreateMailboxes(userID, req.Prefixes, req.DomainID, isAdmin)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "批量创建邮箱成功",
		"data":    mailboxes,
	})
}

// GetMailboxPassword 获取邮箱密码
func (h *MailboxHandler) GetMailboxPassword(c *gin.Context) {
	mailboxIDStr := c.Param("id")
	mailboxID, err := strconv.Atoi(mailboxIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮箱ID格式错误"})
		return
	}

	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")

	password, err := h.mailboxService.GetMailboxPassword(mailboxID, userID, isAdmin)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"password": password,
		},
	})
}

// DeleteMailbox 删除邮箱
func (h *MailboxHandler) DeleteMailbox(c *gin.Context) {
	mailboxIDStr := c.Param("id")
	mailboxID, err := strconv.Atoi(mailboxIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮箱ID格式错误"})
		return
	}

	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")

	err = h.mailboxService.DeleteMailbox(mailboxID, userID, isAdmin)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "邮箱删除成功"})
}

// isValidEmailPrefix 验证邮箱前缀格式
func isValidEmailPrefix(prefix string) bool {
	if len(prefix) == 0 || len(prefix) > 64 {
		return false
	}

	// 简单的邮箱前缀验证
	for _, char := range prefix {
		if !((char >= 'a' && char <= 'z') || 
			 (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || 
			 char == '.' || char == '-' || char == '_') {
			return false
		}
	}

	// 不能以点、横线或下划线开头或结尾
	if strings.HasPrefix(prefix, ".") || strings.HasSuffix(prefix, ".") ||
	   strings.HasPrefix(prefix, "-") || strings.HasSuffix(prefix, "-") ||
	   strings.HasPrefix(prefix, "_") || strings.HasSuffix(prefix, "_") {
		return false
	}

	return true
}

// 管理员邮箱管理接口

// GetAllMailboxes 获取所有邮箱列表（管理员）
func (h *MailboxHandler) GetAllMailboxes(c *gin.Context) {
	mailboxes, err := h.mailboxService.GetAllMailboxes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取邮箱列表失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    mailboxes,
	})
}

// UpdateMailboxStatus 更新邮箱状态（管理员）
func (h *MailboxHandler) UpdateMailboxStatus(c *gin.Context) {
	mailboxIDStr := c.Param("id")
	mailboxID, err := strconv.Atoi(mailboxIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮箱ID格式错误"})
		return
	}

	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	if req.Status != "active" && req.Status != "suspended" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "状态值无效"})
		return
	}

	err = h.mailboxService.UpdateMailboxStatus(mailboxID, req.Status)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "邮箱状态更新成功"})
}

// DeleteMailboxAdmin 删除邮箱（管理员）
func (h *MailboxHandler) DeleteMailboxAdmin(c *gin.Context) {
	mailboxIDStr := c.Param("id")
	mailboxID, err := strconv.Atoi(mailboxIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮箱ID格式错误"})
		return
	}

	err = h.mailboxService.DeleteMailboxAdmin(mailboxID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "邮箱删除成功"})
}

// GetMailboxStats 获取邮箱统计信息（管理员）
func (h *MailboxHandler) GetMailboxStats(c *gin.Context) {
	mailboxIDStr := c.Param("id")
	mailboxID, err := strconv.Atoi(mailboxIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮箱ID格式错误"})
		return
	}

	stats, err := h.mailboxService.GetMailboxStats(mailboxID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}

// GetUserStats 获取用户统计信息
func (h *MailboxHandler) GetUserStats(c *gin.Context) {
	userID := c.GetInt("user_id")

	stats, err := h.mailboxService.GetUserStats(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取统计信息失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    stats,
	})
}
