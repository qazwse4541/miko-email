package handlers

import (
	"net/http"
	"strconv"

	"miko-email/internal/models"
	"miko-email/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

type VerificationHandler struct {
	verificationService *services.VerificationService
	sessionStore        *sessions.CookieStore
}

func NewVerificationHandler(verificationService *services.VerificationService, sessionStore *sessions.CookieStore) *VerificationHandler {
	return &VerificationHandler{
		verificationService: verificationService,
		sessionStore:        sessionStore,
	}
}

// GetRules 获取验证码规则列表
func (h *VerificationHandler) GetRules(c *gin.Context) {
	// 获取当前用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	rules, err := h.verificationService.GetRules(userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取验证码规则失败",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    rules,
	})
}

// CreateRule 创建验证码规则
func (h *VerificationHandler) CreateRule(c *gin.Context) {
	// 获取当前用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Pattern     string `json:"pattern" binding:"required"`
		Type        string `json:"type"`
		Priority    int    `json:"priority"`
		Enabled     bool   `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
			"error":   err.Error(),
		})
		return
	}

	// 设置默认值
	if req.Type == "" {
		req.Type = "custom"
	}

	rule := &models.VerificationRule{
		Name:        req.Name,
		Description: req.Description,
		Pattern:     req.Pattern,
		Type:        req.Type,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
	}

	err := h.verificationService.CreateRule(rule, userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建验证码规则失败",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "验证码规则创建成功",
		"data":    rule,
	})
}

// UpdateRule 更新验证码规则
func (h *VerificationHandler) UpdateRule(c *gin.Context) {
	// 获取当前用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的规则ID",
		})
		return
	}

	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Pattern     string `json:"pattern" binding:"required"`
		Type        string `json:"type"`
		Priority    int    `json:"priority"`
		Enabled     bool   `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
			"error":   err.Error(),
		})
		return
	}

	rule := &models.VerificationRule{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		Pattern:     req.Pattern,
		Type:        req.Type,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
	}

	err = h.verificationService.UpdateRule(rule, userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "更新验证码规则失败",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "验证码规则更新成功",
		"data":    rule,
	})
}

// DeleteRule 删除验证码规则
func (h *VerificationHandler) DeleteRule(c *gin.Context) {
	// 获取当前用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的规则ID",
		})
		return
	}

	err = h.verificationService.DeleteRule(id, userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "删除验证码规则失败",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "验证码规则删除成功",
	})
}

// TestRule 测试验证码规则
func (h *VerificationHandler) TestRule(c *gin.Context) {
	var req struct {
		Pattern     string `json:"pattern" binding:"required"`
		TestContent string `json:"test_content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
			"error":   err.Error(),
		})
		return
	}

	extractedCodes, err := h.verificationService.TestRule(req.Pattern, req.TestContent)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "测试失败",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    extractedCodes,
	})
}

// ExtractCodes 从邮件内容中提取验证码
func (h *VerificationHandler) ExtractCodes(c *gin.Context) {
	// 获取当前用户ID
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	var req struct {
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
			"error":   err.Error(),
		})
		return
	}

	extractedCodes, err := h.verificationService.ExtractVerificationCodes(req.Content, userID.(int))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "提取验证码失败",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    extractedCodes,
	})
}
