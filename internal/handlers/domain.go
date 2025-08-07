package handlers

import (
	"net/http"
	"strconv"

	"miko-email/internal/models"
	"miko-email/internal/services/domain"
	"miko-email/internal/services/dkim"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

type DomainHandler struct {
	domainService *domain.Service
	dkimService   *dkim.Service
	sessionStore  *sessions.CookieStore
}

func NewDomainHandler(domainService *domain.Service, dkimService *dkim.Service, sessionStore *sessions.CookieStore) *DomainHandler {
	return &DomainHandler{
		domainService: domainService,
		dkimService:   dkimService,
		sessionStore:  sessionStore,
	}
}

type CreateDomainRequest struct {
	Name        string `json:"name" binding:"required"`
	MXRecord    string `json:"mx_record"`
	ARecord     string `json:"a_record"`
	TXTRecord   string `json:"txt_record"`
	SPFRecord   string `json:"spf_record"`
	DMARCRecord string `json:"dmarc_record"`
	DKIMRecord  string `json:"dkim_record"`
	PTRRecord   string `json:"ptr_record"`
}

type UpdateDomainRequest struct {
	MXRecord    string `json:"mx_record"`
	ARecord     string `json:"a_record"`
	TXTRecord   string `json:"txt_record"`
	SPFRecord   string `json:"spf_record"`
	DMARCRecord string `json:"dmarc_record"`
	DKIMRecord  string `json:"dkim_record"`
	PTRRecord   string `json:"ptr_record"`
}

// GetDomains 获取域名列表
func (h *DomainHandler) GetDomains(c *gin.Context) {
	domains, err := h.domainService.GetDomains()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取域名列表失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    domains,
	})
}

// GetAvailableDomains 获取可用域名列表
func (h *DomainHandler) GetAvailableDomains(c *gin.Context) {
	domains, err := h.domainService.GetAvailableDomains()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取可用域名列表失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    domains,
	})
}

// CreateDomain 创建域名
func (h *DomainHandler) CreateDomain(c *gin.Context) {
	var req CreateDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	var domain *models.Domain
	var err error

	// 如果有额外的DNS记录，使用完整版本的创建函数
	if req.SPFRecord != "" || req.DMARCRecord != "" || req.DKIMRecord != "" || req.PTRRecord != "" {
		domain, err = h.domainService.CreateDomainWithAllRecords(
			req.Name, req.MXRecord, req.ARecord, req.TXTRecord,
			req.SPFRecord, req.DMARCRecord, req.DKIMRecord, req.PTRRecord)
	} else {
		domain, err = h.domainService.CreateDomain(req.Name, req.MXRecord, req.ARecord, req.TXTRecord)
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "域名创建成功",
		"data":    domain,
	})
}

// CreateDomainSimple 简化创建域名（只需要域名）
func (h *DomainHandler) CreateDomainSimple(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	// 验证域名格式
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "域名不能为空"})
		return
	}

	domain, err := h.domainService.CreateDomainSimple(req.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	// 自动生成DKIM记录
	dkimRecord, err := h.dkimService.GenerateDKIMRecord(req.Name)
	if err == nil && dkimRecord != "" {
		// 更新域名的DKIM记录
		h.domainService.UpdateDomainWithAllRecords(
			domain.ID, domain.MXRecord, domain.ARecord, domain.TXTRecord,
			domain.SPFRecord, domain.DMARCRecord, dkimRecord, domain.PTRRecord)
		domain.DKIMRecord = dkimRecord
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "域名创建成功",
		"data":    domain,
	})
}

// UpdateDomain 更新域名
func (h *DomainHandler) UpdateDomain(c *gin.Context) {
	domainIDStr := c.Param("id")
	domainID, err := strconv.Atoi(domainIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "域名ID格式错误"})
		return
	}

	var req UpdateDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	// 如果有额外的DNS记录，使用完整版本的更新函数
	if req.SPFRecord != "" || req.DMARCRecord != "" || req.DKIMRecord != "" || req.PTRRecord != "" {
		err = h.domainService.UpdateDomainWithAllRecords(
			domainID, req.MXRecord, req.ARecord, req.TXTRecord,
			req.SPFRecord, req.DMARCRecord, req.DKIMRecord, req.PTRRecord)
	} else {
		err = h.domainService.UpdateDomain(domainID, req.MXRecord, req.ARecord, req.TXTRecord)
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "域名更新成功"})
}

// VerifySenderConfiguration 验证发件配置
func (h *DomainHandler) VerifySenderConfiguration(c *gin.Context) {
	domainIDStr := c.Param("id")
	domainID, err := strconv.Atoi(domainIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "域名ID格式错误"})
		return
	}

	domain, err := h.domainService.VerifySenderConfiguration(domainID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "发件配置验证完成",
		"data":    domain,
	})
}

// VerifyReceiverConfiguration 验证收件配置
func (h *DomainHandler) VerifyReceiverConfiguration(c *gin.Context) {
	domainIDStr := c.Param("id")
	domainID, err := strconv.Atoi(domainIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "域名ID格式错误"})
		return
	}

	domain, err := h.domainService.VerifyReceiverConfiguration(domainID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "收件配置验证完成",
		"data":    domain,
	})
}

// DeleteDomain 删除域名
func (h *DomainHandler) DeleteDomain(c *gin.Context) {
	domainIDStr := c.Param("id")
	domainID, err := strconv.Atoi(domainIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "域名ID格式错误"})
		return
	}

	err = h.domainService.DeleteDomain(domainID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "域名删除成功"})
}

// GetDomainUsage 获取域名使用情况
func (h *DomainHandler) GetDomainUsage(c *gin.Context) {
	domainIDStr := c.Param("id")
	domainID, err := strconv.Atoi(domainIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "域名ID格式错误"})
		return
	}

	usage, err := h.domainService.CheckDomainUsage(domainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    usage,
	})
}

// VerifyDomain 验证域名
func (h *DomainHandler) VerifyDomain(c *gin.Context) {
	domainIDStr := c.Param("id")
	domainID, err := strconv.Atoi(domainIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "域名ID格式错误"})
		return
	}

	domain, err := h.domainService.VerifyDomain(domainID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	message := "域名验证完成"
	if domain.IsVerified {
		message = "域名验证成功"
	} else {
		message = "域名验证失败，请检查DNS设置"
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": message,
		"data":    domain,
	})
}

// GetDomainDNSRecords 获取域名DNS记录
func (h *DomainHandler) GetDomainDNSRecords(c *gin.Context) {
	domainName := c.Query("domain")
	if domainName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "域名参数不能为空"})
		return
	}

	records := h.domainService.GetDNSRecords(domainName)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"domain":  domainName,
			"records": records,
		},
	})
}

// GetDKIMRecord 获取域名的DKIM记录
func (h *DomainHandler) GetDKIMRecord(c *gin.Context) {
	domainName := c.Query("domain")
	if domainName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "域名参数不能为空"})
		return
	}

	// 生成或获取DKIM记录
	dkimRecord, err := h.dkimService.GenerateDKIMRecord(domainName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "生成DKIM记录失败: " + err.Error()})
		return
	}

	// 获取公钥
	publicKey, err := h.dkimService.GetPublicKey(domainName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "获取公钥失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"domain":     domainName,
			"selector":   h.dkimService.GetDKIMSelector(),
			"dkim_domain": h.dkimService.GetDKIMDomain(domainName),
			"record":     dkimRecord,
			"public_key": publicKey,
		},
	})
}

// VerifySingleDNSRecord 验证单个DNS记录
func (h *DomainHandler) VerifySingleDNSRecord(c *gin.Context) {
	var req struct {
		Domain       string `json:"domain" binding:"required"`
		RecordType   string `json:"record_type" binding:"required"`
		RecordValue  string `json:"record_value" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请求参数错误"})
		return
	}

	// 验证记录
	isValid, message, err := h.domainService.VerifySingleDNSRecord(req.Domain, req.RecordType, req.RecordValue)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"domain":      req.Domain,
			"record_type": req.RecordType,
			"record_value": req.RecordValue,
			"is_valid":    isValid,
			"message":     message,
		},
	})
}
