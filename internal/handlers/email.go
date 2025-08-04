package handlers

import (
	"encoding/base64"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"miko-email/internal/config"
	"miko-email/internal/models"
	"miko-email/internal/services/email"
	"miko-email/internal/services/forward"
	"miko-email/internal/services/mailbox"
	smtpService "miko-email/internal/services/smtp"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

type EmailHandler struct {
	emailService   *email.Service
	mailboxService *mailbox.Service
	forwardService *forward.Service
	sessionStore   *sessions.CookieStore
	smtpClient     *smtpService.OutboundClient
}

func NewEmailHandler(emailService *email.Service, mailboxService *mailbox.Service, forwardService *forward.Service, sessionStore *sessions.CookieStore) *EmailHandler {
	return &EmailHandler{
		emailService:   emailService,
		mailboxService: mailboxService,
		forwardService: forwardService,
		sessionStore:   sessionStore,
		smtpClient:     smtpService.NewOutboundClientWithDB(mailboxService.GetDB()), // 使用数据库动态获取域名
	}
}

type SendEmailRequest struct {
	From    string `form:"from" binding:"required"`
	To      string `form:"to" binding:"required"`
	CC      string `form:"cc"`
	BCC     string `form:"bcc"`
	Subject string `form:"subject" binding:"required"`
	Content string `form:"content" binding:"required"`
}

type EmailAttachment struct {
	Filename string
	Content  []byte
	MimeType string
}

// SendEmail 发送邮件
func (h *EmailHandler) SendEmail(c *gin.Context) {
	// 设置正确的Content-Type响应头
	c.Header("Content-Type", "application/json; charset=utf-8")

	// 手动解析表单数据以确保UTF-8编码正确处理
	err := c.Request.ParseMultipartForm(32 << 20) // 32MB max memory
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	// 从表单中获取数据
	req := SendEmailRequest{
		From:    c.Request.FormValue("from"),
		To:      c.Request.FormValue("to"),
		CC:      c.Request.FormValue("cc"),
		BCC:     c.Request.FormValue("bcc"),
		Subject: c.Request.FormValue("subject"),
		Content: c.Request.FormValue("content"),
	}

	// 验证必填字段
	if req.From == "" || req.To == "" || req.Subject == "" || req.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	// 处理附件
	var attachments []EmailAttachment
	if c.Request.MultipartForm != nil && c.Request.MultipartForm.File != nil {
		files := c.Request.MultipartForm.File["attachments"]
		for _, fileHeader := range files {
			file, err := fileHeader.Open()
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "附件读取失败: " + err.Error()})
				return
			}
			defer file.Close()

			// 读取文件内容
			content := make([]byte, fileHeader.Size)
			_, err = file.Read(content)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "附件内容读取失败: " + err.Error()})
				return
			}

			// 检查文件大小限制（10MB）
			if fileHeader.Size > 10*1024*1024 {
				c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": fmt.Sprintf("附件 %s 超过10MB限制", fileHeader.Filename)})
				return
			}

			attachments = append(attachments, EmailAttachment{
				Filename: fileHeader.Filename,
				Content:  content,
				MimeType: fileHeader.Header.Get("Content-Type"),
			})
		}
	}

	// 获取当前用户信息
	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "未登录"})
		return
	}

	// 验证发件邮箱是否属于当前用户
	fromMailbox, err := h.mailboxService.GetMailboxByEmail(req.From)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "发件邮箱不存在"})
		return
	}

	// 检查邮箱所有权
	if isAdmin {
		if fromMailbox.AdminID == nil || *fromMailbox.AdminID != userID {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "无权使用此邮箱发送邮件"})
			return
		}
	} else {
		if fromMailbox.UserID == nil || *fromMailbox.UserID != userID {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "无权使用此邮箱发送邮件"})
			return
		}
	}

	// 处理收件人列表（支持多个收件人）
	recipients := strings.Split(req.To, ",")
	for i, recipient := range recipients {
		recipients[i] = strings.TrimSpace(recipient)
	}

	// 发送邮件到每个收件人
	var successfulSends []string // 记录成功发送的收件人

	for _, recipient := range recipients {
		if recipient == "" {
			continue
		}

		// 所有邮件都通过SMTP服务器发送，确保一致的处理流程
		var sendErr error

		// 检查收件人邮箱是否存在于系统中
		_, err := h.mailboxService.GetMailboxByEmail(recipient)
		if err != nil {
			// 收件人不在系统中，检查是否为有效的外部邮箱
			if !h.smtpClient.IsExternalEmail(recipient) {
				// 不是有效的外部邮箱，跳过
				continue
			}
		}

		// 统一通过MX发送邮件（无论是内部还是外部邮件）
		if len(attachments) > 0 {
			// 构建MIME邮件内容
			mimeContent := h.buildMIMEMessage(req.From, recipient, req.Subject, req.Content, attachments)
			sendErr = h.smtpClient.SendMIMEEmail(req.From, recipient, mimeContent)
		} else {
			sendErr = h.smtpClient.SendEmail(req.From, recipient, req.Subject, req.Content)
		}

		// 记录发送尝试
		h.smtpClient.LogSendAttempt(req.From, recipient, req.Subject, sendErr)

		if sendErr == nil {
			// 发送成功，记录成功的收件人
			successfulSends = append(successfulSends, recipient)
		} else {
			// 发送失败，继续处理下一个收件人
			log.Printf("邮件发送失败 %s -> %s: %v", req.From, recipient, sendErr)
			continue
		}
	}

	// 只有在有成功发送的邮件时，才保存到发件人的已发送文件夹
	for _, recipient := range successfulSends {
		err := h.emailService.SaveEmailToSent(fromMailbox.ID, req.From, recipient, req.Subject, req.Content)
		if err != nil {
			// 保存到已发送失败，记录日志但不影响主要功能
			continue
		}
	}

	// 根据发送结果返回相应消息
	if len(successfulSends) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "没有邮件发送成功"})
	} else if len(successfulSends) == len(recipients) {
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "所有邮件发送成功"})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": fmt.Sprintf("部分邮件发送成功 (%d/%d)", len(successfulSends), len(recipients)),
		})
	}
}

// GetEmails 获取邮件列表
func (h *EmailHandler) GetEmails(c *gin.Context) {
	// 设置正确的Content-Type响应头
	c.Header("Content-Type", "application/json; charset=utf-8")

	// 获取当前用户信息
	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "未登录"})
		return
	}

	// 获取查询参数
	mailboxEmail := c.Query("mailbox")
	emailType := c.DefaultQuery("type", "inbox") // inbox, sent, trash
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "20")

	page, _ := strconv.Atoi(pageStr)
	limit, _ := strconv.Atoi(limitStr)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	// 如果没有指定邮箱，显示所有邮箱的邮件
	var emails []models.Email
	var total int
	var err error

	if mailboxEmail != "" {
		// 指定了邮箱，只显示该邮箱的邮件
		targetMailbox, err := h.mailboxService.GetMailboxByEmail(mailboxEmail)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮箱不存在"})
			return
		}

		// 检查邮箱所有权
		if isAdmin {
			if targetMailbox.AdminID == nil || *targetMailbox.AdminID != userID {
				c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "无权访问此邮箱"})
				return
			}
		} else {
			if targetMailbox.UserID == nil || *targetMailbox.UserID != userID {
				c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "无权访问此邮箱"})
				return
			}
		}

		// 获取指定邮箱的邮件列表
		emails, total, err = h.emailService.GetEmails(targetMailbox.ID, emailType, page, limit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取邮件失败"})
			return
		}
	} else {
		// 没有指定邮箱，显示所有邮箱的邮件
		emails, total, err = h.emailService.GetAllUserEmails(userID, isAdmin, emailType, page, limit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取邮件失败"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    emails,
		"total":   total,
		"page":    page,
		"limit":   limit,
	})
}

// GetEmailByID 获取单个邮件详情
func (h *EmailHandler) GetEmailByID(c *gin.Context) {
	// 设置正确的Content-Type响应头
	c.Header("Content-Type", "application/json; charset=utf-8")

	// 获取当前用户信息
	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "未登录"})
		return
	}

	emailIDStr := c.Param("id")
	emailID, err := strconv.Atoi(emailIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮件ID无效"})
		return
	}

	mailboxEmail := c.Query("mailbox")

	var email *models.Email
	var targetMailboxID int

	if mailboxEmail != "" {
		// 指定邮箱模式
		// 获取邮箱信息
		targetMailbox, mailboxErr := h.mailboxService.GetMailboxByEmail(mailboxEmail)
		if mailboxErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮箱不存在"})
			return
		}

		// 检查邮箱所有权
		if isAdmin {
			if targetMailbox.AdminID == nil || *targetMailbox.AdminID != userID {
				c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "无权访问此邮箱"})
				return
			}
		} else {
			if targetMailbox.UserID == nil || *targetMailbox.UserID != userID {
				c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "无权访问此邮箱"})
				return
			}
		}

		targetMailboxID = targetMailbox.ID
		// 获取邮件详情
		email, err = h.emailService.GetEmailByID(emailID, targetMailbox.ID)
	} else {
		// 全部邮箱模式 - 查询用户所有邮箱的邮件
		email, err = h.emailService.GetEmailByIDForUser(emailID, userID)
		if err == nil {
			targetMailboxID = email.MailboxID
		}
	}

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "邮件不存在或无权访问"})
		return
	}

	// 标记为已读
	h.emailService.MarkAsRead(emailID, targetMailboxID)

	c.JSON(http.StatusOK, gin.H{"success": true, "data": email})
}

// MarkAllEmailsAsRead 标记邮箱中所有邮件为已读
func (h *EmailHandler) MarkAllEmailsAsRead(c *gin.Context) {
	// 获取当前用户信息
	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "未登录"})
		return
	}

	// 获取邮箱参数
	mailboxEmail := c.Query("mailbox")
	if mailboxEmail == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮箱参数不能为空"})
		return
	}

	// 查找邮箱
	targetMailbox, err := h.mailboxService.GetMailboxByEmail(mailboxEmail)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "邮箱不存在"})
		return
	}

	// 检查邮箱所有权
	if isAdmin {
		if targetMailbox.AdminID == nil || *targetMailbox.AdminID != userID {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "无权访问此邮箱"})
			return
		}
	} else {
		if targetMailbox.UserID == nil || *targetMailbox.UserID != userID {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "无权访问此邮箱"})
			return
		}
	}

	// 标记所有邮件为已读
	err = h.emailService.MarkAllAsRead(targetMailbox.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "标记邮件失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "所有邮件已标记为已读"})
}

// DeleteEmail 删除邮件
func (h *EmailHandler) DeleteEmail(c *gin.Context) {
	c.Header("Content-Type", "application/json; charset=utf-8")

	emailIDStr := c.Param("id")
	emailID, err := strconv.Atoi(emailIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "邮件ID格式错误"})
		return
	}

	userID := c.GetInt("user_id")
	isAdmin := c.GetBool("is_admin")

	// 首先需要获取用户的邮箱来验证权限
	// 这里我们需要一个更简单的方法来验证邮件所有权
	// 让我们直接在删除时验证权限

	// 获取用户的邮箱列表来验证权限
	userMailboxes, err := h.mailboxService.GetUserMailboxesRaw(userID, isAdmin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取邮箱列表失败"})
		return
	}

	if len(userMailboxes) == 0 {
		c.JSON(http.StatusForbidden, gin.H{"success": false, "message": "无权删除邮件"})
		return
	}

	// 使用第一个邮箱的ID来获取邮件（这里需要改进逻辑）
	mailboxID := userMailboxes[0].ID

	// 验证邮件是否存在且属于用户的邮箱
	_, err = h.emailService.GetEmailByID(emailID, mailboxID)
	if err != nil {
		// 尝试其他邮箱
		found := false
		for _, mb := range userMailboxes {
			_, err = h.emailService.GetEmailByID(emailID, mb.ID)
			if err == nil {
				mailboxID = mb.ID
				found = true
				break
			}
		}
		if !found {
			c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "邮件不存在或无权访问"})
			return
		}
	}

	// 删除邮件
	err = h.emailService.DeleteEmail(emailID, mailboxID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "删除邮件失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "邮件删除成功"})
}

// 使用转发服务中的结构体，这里不需要重复定义

// GetForwardRules 获取转发规则列表
func (h *EmailHandler) GetForwardRules(c *gin.Context) {
	c.Header("Content-Type", "application/json; charset=utf-8")

	username := c.GetString("username")
	userID := c.GetInt("user_id")

	rules, err := h.forwardService.GetForwardRulesByUser(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取转发规则失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    rules,
		"message": fmt.Sprintf("用户 %s 的转发规则", username),
	})
}

// CreateForwardRule 创建转发规则
func (h *EmailHandler) CreateForwardRule(c *gin.Context) {
	c.Header("Content-Type", "application/json; charset=utf-8")

	var req forward.CreateForwardRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	username := c.GetString("username")
	userID := c.GetInt("user_id")

	newRule, err := h.forwardService.CreateForwardRule(userID, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    newRule,
		"message": fmt.Sprintf("用户 %s 创建转发规则成功", username),
	})
}

// GetForwardRule 获取单个转发规则
func (h *EmailHandler) GetForwardRule(c *gin.Context) {
	c.Header("Content-Type", "application/json; charset=utf-8")

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的规则ID",
		})
		return
	}

	userID := c.GetInt("user_id")

	rule, err := h.forwardService.GetForwardRuleByID(id, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    rule,
	})
}

// UpdateForwardRule 更新转发规则
func (h *EmailHandler) UpdateForwardRule(c *gin.Context) {
	c.Header("Content-Type", "application/json; charset=utf-8")

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的规则ID",
		})
		return
	}

	var req forward.CreateForwardRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	userID := c.GetInt("user_id")

	err = h.forwardService.UpdateForwardRule(id, userID, req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("转发规则 %d 更新成功", id),
	})
}

// DeleteForwardRule 删除转发规则
func (h *EmailHandler) DeleteForwardRule(c *gin.Context) {
	c.Header("Content-Type", "application/json; charset=utf-8")

	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的规则ID",
		})
		return
	}

	userID := c.GetInt("user_id")

	err = h.forwardService.DeleteForwardRule(id, userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("转发规则 %d 删除成功", id),
	})
}

// ToggleForwardRule 切换转发规则状态
func (h *EmailHandler) ToggleForwardRule(c *gin.Context) {
	c.Header("Content-Type", "application/json; charset=utf-8")

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
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	userID := c.GetInt("user_id")

	err = h.forwardService.ToggleForwardRule(id, userID, req.Enabled)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	status := "启用"
	if !req.Enabled {
		status = "禁用"
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("转发规则 %d 已%s", id, status),
	})
}

// TestForwardRule 测试转发规则
func (h *EmailHandler) TestForwardRule(c *gin.Context) {
	c.Header("Content-Type", "application/json; charset=utf-8")

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
		Subject string `json:"subject"`
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误: " + err.Error(),
		})
		return
	}

	// 获取用户ID
	userID := c.GetInt("user_id")

	// 获取转发规则详情
	rule, err := h.forwardService.GetForwardRuleByID(id, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "转发规则不存在或无权限访问",
		})
		return
	}

	// 检查规则是否启用
	if !rule.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "转发规则已禁用，无法测试",
		})
		return
	}

	// 构建测试邮件的主题和内容
	testSubject := req.Subject
	if testSubject == "" {
		testSubject = "测试转发邮件 - " + time.Now().Format("2006-01-02 15:04:05")
	}

	testContent := req.Content
	if testContent == "" {
		testContent = fmt.Sprintf(`这是一封测试转发功能的邮件。

测试时间: %s
源邮箱: %s
目标邮箱: %s
转发规则ID: %d

如果您收到这封邮件，说明转发功能正常工作。`,
			time.Now().Format("2006-01-02 15:04:05"),
			rule.SourceEmail,
			rule.TargetEmail,
			rule.ID)
	}

	// 发送测试邮件到源邮箱，触发转发
	err = h.emailService.SendTestForwardEmail(rule.SourceEmail, rule.TargetEmail, testSubject, testContent, rule)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "测试邮件发送失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("测试邮件已发送到 %s，如果转发规则正常，您应该会在 %s 收到转发邮件", rule.SourceEmail, rule.TargetEmail),
	})
}

// GetForwardStatistics 获取转发统计信息
func (h *EmailHandler) GetForwardStatistics(c *gin.Context) {
	c.Header("Content-Type", "application/json; charset=utf-8")

	userID := c.GetInt("user_id")

	stats, err := h.forwardService.GetForwardStatistics(userID)
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



// buildMIMEMessage 构建MIME格式的邮件内容
func (h *EmailHandler) buildMIMEMessage(from, to, subject, body string, attachments []EmailAttachment) string {
	boundary := fmt.Sprintf("----=_NextPart_%d", time.Now().Unix())

	var message strings.Builder

	// 邮件头部
	message.WriteString(fmt.Sprintf("From: %s\r\n", from))
	message.WriteString(fmt.Sprintf("To: %s\r\n", to))
	message.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	message.WriteString("MIME-Version: 1.0\r\n")
	message.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
	message.WriteString("\r\n")

	// 邮件正文部分
	message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	message.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	message.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	message.WriteString("\r\n")
	message.WriteString(body)
	message.WriteString("\r\n")

	// 附件部分
	for _, attachment := range attachments {
		message.WriteString(fmt.Sprintf("--%s\r\n", boundary))

		// 确定MIME类型
		mimeType := attachment.MimeType
		if mimeType == "" {
			mimeType = mime.TypeByExtension(filepath.Ext(attachment.Filename))
			if mimeType == "" {
				mimeType = "application/octet-stream"
			}
		}

		message.WriteString(fmt.Sprintf("Content-Type: %s\r\n", mimeType))
		message.WriteString("Content-Transfer-Encoding: base64\r\n")
		message.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", attachment.Filename))
		message.WriteString("\r\n")

		// Base64编码附件内容
		encoded := base64.StdEncoding.EncodeToString(attachment.Content)
		// 每76个字符换行
		for i := 0; i < len(encoded); i += 76 {
			end := i + 76
			if end > len(encoded) {
				end = len(encoded)
			}
			message.WriteString(encoded[i:end])
			message.WriteString("\r\n")
		}
	}

	// 结束边界
	message.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	return message.String()
}

// sendThroughLocalSMTP 通过本地SMTP服务器发送邮件
func (h *EmailHandler) sendThroughLocalSMTP(from, to, subject, body string) error {
	// 获取配置
	cfg := config.Load()

	// 构建邮件内容
	message := h.buildEmailMessage(from, to, subject, body)

	// 获取本地SMTP端口（优先使用587端口）
	smtpPorts := cfg.GetSMTPPorts()
	var port string
	for _, p := range smtpPorts {
		if p == "587" {
			port = p
			break
		}
	}
	if port == "" && len(smtpPorts) > 0 {
		port = smtpPorts[0] // 使用第一个可用端口
	}
	if port == "" {
		port = "25" // 默认端口
	}

	// 连接到本地SMTP服务器
	addr := fmt.Sprintf("127.0.0.1:%s", port)

	// 设置连接超时
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("连接本地SMTP服务器失败: %v", err)
	}
	defer conn.Close()

	// 创建SMTP客户端
	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %v", err)
	}
	defer client.Close()

	// 设置发件人
	if err = client.Mail(from); err != nil {
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// 设置收件人
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("设置收件人失败: %v", err)
	}

	// 发送邮件内容
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("开始发送邮件内容失败: %v", err)
	}
	defer wc.Close()

	_, err = wc.Write(message)
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}

	log.Printf("✅ 通过本地SMTP发送成功: %s -> %s", from, to)
	return nil
}

// buildEmailMessage 构建邮件消息
func (h *EmailHandler) buildEmailMessage(from, to, subject, body string) []byte {
	// 检测内容类型
	var contentType string
	if h.isHTMLContent(body) {
		contentType = "text/html; charset=UTF-8"
	} else {
		contentType = "text/plain; charset=UTF-8"
	}

	// 构建标准的邮件格式
	message := fmt.Sprintf("From: %s\r\n", from)
	message += fmt.Sprintf("To: %s\r\n", to)
	message += fmt.Sprintf("Subject: %s\r\n", subject)
	message += "MIME-Version: 1.0\r\n"
	message += fmt.Sprintf("Content-Type: %s\r\n", contentType)
	message += "Content-Transfer-Encoding: 8bit\r\n"
	message += fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	message += "\r\n"
	message += body

	return []byte(message)
}

// isHTMLContent 检测内容是否为HTML格式
func (h *EmailHandler) isHTMLContent(content string) bool {
	// 检查是否包含HTML标签
	htmlTags := []string{"<html", "<body", "<div", "<p>", "<br", "<span", "<table", "<tr", "<td", "<h1", "<h2", "<h3", "<h4", "<h5", "<h6", "<ul", "<ol", "<li", "<a ", "<img", "<style", "<script"}

	contentLower := strings.ToLower(content)
	for _, tag := range htmlTags {
		if strings.Contains(contentLower, tag) {
			return true
		}
	}

	return false
}

// GetVerificationCode 获取邮件验证码
func (h *EmailHandler) GetVerificationCode(c *gin.Context) {
	c.Header("Content-Type", "application/json; charset=utf-8")

	userID := c.GetInt("user_id")
	mailbox := c.Query("mailbox")
	sender := c.Query("sender")     // 可选：指定发件人过滤
	subject := c.Query("subject")   // 可选：指定主题关键词过滤
	emailIDStr := c.Query("email_id") // 可选：指定特定邮件ID
	limitStr := c.DefaultQuery("limit", "10") // 默认查询最近10封邮件

	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		limit = 10
	}

	// 如果指定了邮箱，验证邮箱是否属于当前用户
	var mailboxInfo *models.Mailbox
	if mailbox != "" {
		var err error
		mailboxInfo, err = h.mailboxService.GetMailboxByEmail(mailbox)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"success": false,
				"message": "邮箱不存在",
			})
			return
		}

		if mailboxInfo.UserID == nil || *mailboxInfo.UserID != userID {
			c.JSON(http.StatusForbidden, gin.H{
				"success": false,
				"message": "无权访问此邮箱",
			})
			return
		}
	}

	var emails []models.Email

	// 如果指定了email_id，只查询特定邮件
	if emailIDStr != "" {
		emailID, parseErr := strconv.Atoi(emailIDStr)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "邮件ID格式错误",
			})
			return
		}

		if mailbox != "" {
			// 获取特定邮件（指定邮箱）
			email, getErr := h.emailService.GetEmailByID(emailID, mailboxInfo.ID)
			if getErr != nil {
				c.JSON(http.StatusNotFound, gin.H{
					"success": false,
					"message": "邮件不存在或无权访问",
				})
				return
			}
			emails = []models.Email{*email}
		} else {
			// 获取特定邮件（所有邮箱）
			email, getErr := h.emailService.GetEmailByIDForUser(emailID, userID)
			if getErr != nil {
				c.JSON(http.StatusNotFound, gin.H{
					"success": false,
					"message": "邮件不存在或无权访问",
				})
				return
			}
			emails = []models.Email{*email}
		}
	} else {
		// 获取邮件列表
		var getErr error
		if mailbox != "" {
			// 获取指定邮箱的邮件
			emails, _, getErr = h.emailService.GetEmails(mailboxInfo.ID, "inbox", 1, limit)
		} else {
			// 获取用户所有邮箱的邮件
			emails, _, getErr = h.emailService.GetEmailsForUser(userID, "inbox", 1, limit)
		}
		if getErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "获取邮件失败: " + getErr.Error(),
			})
			return
		}
	}

	// 提取验证码
	var results []map[string]interface{}

	for _, email := range emails {
		// 如果指定了email_id，跳过过滤条件检查
		if emailIDStr == "" {
			// 应用过滤条件
			if sender != "" && !strings.Contains(strings.ToLower(email.FromAddr), strings.ToLower(sender)) {
				continue
			}
			if subject != "" && !strings.Contains(strings.ToLower(email.Subject), strings.ToLower(subject)) {
				continue
			}
		}

		// 提取验证码
		codes := extractVerificationCodes(email.Body)
		if len(codes) > 0 {
			results = append(results, map[string]interface{}{
				"email_id":    email.ID,
				"from":        email.FromAddr,
				"subject":     email.Subject,
				"created_at":  email.CreatedAt,
				"codes":       codes,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    results,
		"count":   len(results),
	})
}

// extractVerificationCodes 从邮件内容中提取验证码
func extractVerificationCodes(content string) []string {
	var codes []string

	// 常见的验证码模式
	patterns := []string{
		`\b\d{4,8}\b`,                    // 4-8位纯数字
		`\b[A-Z0-9]{4,8}\b`,             // 4-8位大写字母和数字组合
		`\b[a-zA-Z0-9]{4,8}\b`,          // 4-8位字母数字组合
		`验证码[：:\s]*([A-Za-z0-9]{4,8})`,   // 中文"验证码"后跟代码
		`验证码[：:\s]*(\d{4,8})`,           // 中文"验证码"后跟数字
		`code[：:\s]*([A-Za-z0-9]{4,8})`,   // 英文"code"后跟代码
		`Code[：:\s]*([A-Za-z0-9]{4,8})`,   // 英文"Code"后跟代码
		`CODE[：:\s]*([A-Za-z0-9]{4,8})`,   // 英文"CODE"后跟代码
	}

	// 使用正则表达式提取
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)

		for _, match := range matches {
			if len(match) > 1 {
				// 有捕获组的情况
				code := strings.TrimSpace(match[1])
				if isValidVerificationCode(code) {
					codes = append(codes, code)
				}
			} else if len(match) > 0 {
				// 没有捕获组的情况
				code := strings.TrimSpace(match[0])
				if isValidVerificationCode(code) {
					codes = append(codes, code)
				}
			}
		}
	}

	// 去重
	seen := make(map[string]bool)
	var uniqueCodes []string
	for _, code := range codes {
		if !seen[code] {
			seen[code] = true
			uniqueCodes = append(uniqueCodes, code)
		}
	}

	return uniqueCodes
}

// isValidVerificationCode 验证是否为有效的验证码
func isValidVerificationCode(code string) bool {
	// 长度检查
	if len(code) < 4 || len(code) > 8 {
		return false
	}

	// 排除一些明显不是验证码的内容
	excludePatterns := []string{
		`^\d{4}$`,  // 排除4位年份
		`^(19|20)\d{2}$`, // 排除年份
		`^(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$`, // 排除日期格式
	}

	for _, pattern := range excludePatterns {
		matched, _ := regexp.MatchString(pattern, code)
		if matched {
			return false
		}
	}

	return true
}
