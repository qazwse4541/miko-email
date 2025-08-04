package smtp

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"regexp"
	"strings"
	"time"

	"miko-email/internal/services/dkim"
)

// OutboundClient MX直接发送客户端
type OutboundClient struct {
	domain      string        // 本地域名（兼容性保留）
	db          *sql.DB       // 数据库连接，用于动态获取域名
	dkimService *dkim.Service // DKIM签名服务
}

// NewOutboundClient 创建MX发送客户端（兼容性保留）
func NewOutboundClient(domain string) *OutboundClient {
	return &OutboundClient{
		domain: domain,
	}
}

// NewOutboundClientWithDB 创建支持多域名的MX发送客户端
func NewOutboundClientWithDB(db *sql.DB) *OutboundClient {
	return &OutboundClient{
		db:          db,
		dkimService: dkim.NewService("./dkim_keys"),
	}
}

// SendEmail 通过MX记录直接发送邮件
func (c *OutboundClient) SendEmail(from, to, subject, body string) error {
	// 验证发件人是否为本域名邮箱
	if !c.isLocalEmail(from) {
		return fmt.Errorf("发件人必须是本域名邮箱: %s", from)
	}

	// 提取收件人域名
	toDomain := extractDomain(to)
	if toDomain == "" {
		return fmt.Errorf("无效的收件人邮箱地址: %s", to)
	}

	log.Printf("开始MX直接发送: %s -> %s", from, to)

	// 检查是否为本地域名，如果是，使用本地MX服务器
	if c.isLocalDomain(toDomain) {
		log.Printf("本地域名邮件，使用本地MX服务器: %s", toDomain)
		return c.sendToLocalMX(from, to, subject, body)
	}

	// 查询收件人域名的MX记录
	mxRecords, err := net.LookupMX(toDomain)
	if err != nil {
		return fmt.Errorf("查询MX记录失败 (%s): %v", toDomain, err)
	}

	if len(mxRecords) == 0 {
		return fmt.Errorf("域名 %s 没有MX记录", toDomain)
	}

	// 按优先级排序，选择优先级最高的MX记录
	var bestMX *net.MX
	for _, mx := range mxRecords {
		if bestMX == nil || mx.Pref < bestMX.Pref {
			bestMX = mx
		}
	}

	mxHost := strings.TrimSuffix(bestMX.Host, ".")
	log.Printf("使用MX服务器: %s (优先级: %d)", mxHost, bestMX.Pref)

	// 构建邮件内容
	message := c.buildMessage(from, to, subject, body)

	// 尝试连接到MX服务器的25端口
	addr := fmt.Sprintf("%s:25", mxHost)

	// 使用重试机制
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		log.Printf("尝试连接MX服务器 %s (第%d次)", addr, i+1)

		err = c.sendDirectSMTP(addr, from, to, message, mxHost)
		if err == nil {
			log.Printf("✅ MX直接发送成功: %s -> %s", from, to)
			return nil
		}

		log.Printf("MX发送失败 (第%d次): %v", i+1, err)

		// 如果不是最后一次重试，等待一段时间再重试
		if i < maxRetries-1 {
			time.Sleep(time.Duration(i+1) * 2 * time.Second)
		}
	}

	return fmt.Errorf("MX直接发送失败，已重试%d次: %v", maxRetries, err)
}

// sendDirectSMTP 直接SMTP发送（无认证）
func (c *OutboundClient) sendDirectSMTP(addr, from, to string, message []byte, hostname string) error {
	// 连接到SMTP服务器
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer conn.Close()

	// 创建SMTP客户端
	client, err := smtp.NewClient(conn, hostname)
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %v", err)
	}
	defer client.Close()

	// 设置发件人
	log.Printf("设置发件人: %s", from)
	if err = client.Mail(from); err != nil {
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// 设置收件人
	log.Printf("设置收件人: %s", to)
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("设置收件人失败: %v", err)
	}

	// 发送邮件内容
	log.Printf("开始发送邮件内容")
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("开始发送邮件内容失败: %v", err)
	}

	_, err = w.Write(message)
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("关闭数据写入器失败: %v", err)
	}

	log.Printf("邮件内容发送完成")
	return client.Quit()
}

// buildMessage 构建邮件消息
func (c *OutboundClient) buildMessage(from, to, subject, body string) []byte {
	// 检测邮件内容类型
	var cleanBody string
	var contentType string

	if isHTMLContent(body) {
		// 保留HTML内容
		cleanBody = body
		contentType = "text/html; charset=UTF-8"
	} else {
		// 清理HTML标签，确保发送纯文本邮件
		cleanBody = stripHTMLTags(body)
		contentType = "text/plain; charset=UTF-8"
	}

	// 获取发件人域名
	fromDomain := extractDomain(from)
	if fromDomain == "" {
		fromDomain = c.domain
	}

	// 构建邮件头
	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = to
	headers["Date"] = time.Now().Format(time.RFC1123Z)
	headers["Message-ID"] = fmt.Sprintf("<%d.%s@%s>", time.Now().Unix(), generateRandomID(), fromDomain)

	// 对主题进行MIME编码（如果包含非ASCII字符）
	if needsMIMEEncoding(subject) {
		headers["Subject"] = encodeMIMEHeader(subject)
	} else {
		headers["Subject"] = subject
	}

	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = contentType

	// 对邮件正文进行编码处理
	var encodedBody string
	var transferEncoding string

	if needsMIMEEncoding(cleanBody) {
		// 使用Base64编码处理包含中文的内容
		encodedBody = base64.StdEncoding.EncodeToString([]byte(cleanBody))
		transferEncoding = "base64"

		// 将Base64编码的内容按76字符换行（RFC标准）
		var formattedBody strings.Builder
		for i := 0; i < len(encodedBody); i += 76 {
			end := i + 76
			if end > len(encodedBody) {
				end = len(encodedBody)
			}
			formattedBody.WriteString(encodedBody[i:end])
			if end < len(encodedBody) {
				formattedBody.WriteString("\r\n")
			}
		}
		encodedBody = formattedBody.String()
	} else {
		// 纯ASCII内容，直接使用
		encodedBody = cleanBody
		transferEncoding = "7bit"
	}

	headers["Content-Transfer-Encoding"] = transferEncoding

	// 添加自定义头部标识
	headers["X-Mailer"] = "Miko Email System"

	// 构建完整消息
	var message strings.Builder
	for k, v := range headers {
		message.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	message.WriteString("\r\n")
	message.WriteString(encodedBody)

	emailContent := []byte(message.String())

	// 如果有DKIM服务，对邮件进行签名
	if c.dkimService != nil && fromDomain != "" {
		signedContent, err := c.dkimService.SignEmail(fromDomain, "default", emailContent)
		if err != nil {
			log.Printf("DKIM签名失败: %v", err)
			// 签名失败时返回原始邮件
			return emailContent
		}
		log.Printf("邮件已进行DKIM签名，域名: %s", fromDomain)
		return signedContent
	}

	return emailContent
}

// isLocalEmail 检查是否为本地域名邮箱
func (c *OutboundClient) isLocalEmail(email string) bool {
	// 首先检查是否为系统中存在的邮箱
	if c.db != nil {
		var count int
		err := c.db.QueryRow("SELECT COUNT(*) FROM mailboxes WHERE email = ? AND is_active = 1", email).Scan(&count)
		if err == nil && count > 0 {
			return true
		}
	}

	// 然后检查域名
	domain := extractDomain(email)
	return c.isLocalDomain(domain)
}

// isLocalDomain 检查是否为本地域名
func (c *OutboundClient) isLocalDomain(domain string) bool {
	// 如果有数据库连接，从数据库查询所有活跃域名
	if c.db != nil {
		var count int
		err := c.db.QueryRow("SELECT COUNT(*) FROM domains WHERE name = ? AND is_active = 1", domain).Scan(&count)
		if err == nil && count > 0 {
			return true
		}

		// 如果domains表中没有记录，检查是否有该域名的邮箱
		err = c.db.QueryRow("SELECT COUNT(*) FROM mailboxes WHERE email LIKE ? AND is_active = 1", "%@"+domain).Scan(&count)
		if err == nil && count > 0 {
			return true
		}
	}

	// 默认支持的本地域名
	localDomains := []string{"localhost", "jbjj.site", "gmns.top"}
	for _, localDomain := range localDomains {
		if domain == localDomain {
			return true
		}
	}

	// 兼容性：如果没有数据库连接，使用固定域名
	return domain == c.domain
}

// sendToLocalMX 发送邮件到本地MX服务器
func (c *OutboundClient) sendToLocalMX(from, to, subject, body string) error {
	// 构建邮件内容
	message := c.buildMessage(from, to, subject, body)

	// 根据发件人邮箱获取域名
	fromDomain := extractDomain(from)
	localDomain := c.getDomainForSender(fromDomain)

	// 本地MX服务器地址和端口
	localMXServers := []string{
		"127.0.0.1:25",
		"127.0.0.1:587",
		"127.0.0.1:465",
	}

	// 尝试连接到本地MX服务器
	var lastErr error
	for _, addr := range localMXServers {
		log.Printf("尝试连接本地MX服务器: %s (域名: %s)", addr, localDomain)

		err := c.sendDirectSMTP(addr, from, to, message, localDomain)
		if err == nil {
			log.Printf("✅ 本地MX发送成功: %s -> %s (通过 %s, 域名: %s)", from, to, addr, localDomain)
			return nil
		}

		log.Printf("本地MX服务器 %s 连接失败: %v", addr, err)
		lastErr = err
	}

	return fmt.Errorf("所有本地MX服务器连接失败，最后错误: %v", lastErr)
}

// getDomainForSender 根据发件人域名获取对应的域名配置
func (c *OutboundClient) getDomainForSender(senderDomain string) string {
	// 如果发件人域名不为空且不是localhost，直接使用发件人域名
	if senderDomain != "" && senderDomain != "localhost" {
		// 如果有数据库连接，验证该域名是否在系统中配置
		if c.db != nil {
			var count int
			err := c.db.QueryRow("SELECT COUNT(*) FROM domains WHERE name = ? AND is_active = 1", senderDomain).Scan(&count)
			if err == nil && count > 0 {
				return senderDomain
			}
		}
		// 即使数据库中没有，也使用发件人域名（向后兼容）
		return senderDomain
	}

	// 如果发件人域名为空或是localhost，尝试从数据库获取第一个活跃域名
	if c.db != nil {
		var domain string
		err := c.db.QueryRow("SELECT name FROM domains WHERE is_active = 1 AND name != 'localhost' ORDER BY id LIMIT 1").Scan(&domain)
		if err == nil && domain != "" {
			return domain
		}
	}

	// 如果有配置的域名且不是localhost，使用它
	if c.domain != "" && c.domain != "localhost" {
		return c.domain
	}

	// 最后的默认值
	return "mail.local"
}

// extractDomain 提取邮箱域名
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// IsExternalEmail 检查是否为外部邮箱
func (c *OutboundClient) IsExternalEmail(email string) bool {
	if !strings.Contains(email, "@") {
		return false
	}

	domain := extractDomain(email)

	// 如果有数据库连接，从数据库查询所有活跃域名
	if c.db != nil {
		var count int
		err := c.db.QueryRow("SELECT COUNT(*) FROM domains WHERE name = ? AND is_active = 1", domain).Scan(&count)
		if err != nil {
			log.Printf("查询域名失败: %v", err)
			return true // 查询失败时假设是外部邮箱
		}
		return count == 0 && domain != "localhost"
	}

	// 兼容性：如果没有数据库连接，使用固定域名
	return domain != c.domain && domain != "localhost"
}

// needsMIMEEncoding 检查字符串是否需要MIME编码
func needsMIMEEncoding(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

// encodeMIMEHeader 对邮件头部进行MIME编码
func encodeMIMEHeader(s string) string {
	if !needsMIMEEncoding(s) {
		return s
	}

	// 使用Base64编码
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	return fmt.Sprintf("=?UTF-8?B?%s?=", encoded)
}

// generateRandomID 生成随机ID
func generateRandomID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// isHTMLContent 检测内容是否为HTML格式
func isHTMLContent(content string) bool {
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

// stripHTMLTags 清理HTML标签，返回纯文本
func stripHTMLTags(html string) string {
	// 移除HTML标签
	re := regexp.MustCompile(`<[^>]*>`)
	text := re.ReplaceAllString(html, "")

	// 清理多余的空白字符
	text = strings.TrimSpace(text)

	// 将HTML实体转换为普通字符
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&quot;", "\"")
	text = strings.ReplaceAll(text, "&#39;", "'")

	return text
}

// LogSendAttempt 记录发送尝试
func (c *OutboundClient) LogSendAttempt(from, to, subject string, err error) {
	if err != nil {
		log.Printf("❌ MX发送失败 - From: %s, To: %s, Subject: %s, Error: %v", from, to, subject, err)
	} else {
		log.Printf("✅ MX发送成功 - From: %s, To: %s, Subject: %s", from, to, subject)
	}
}

// SendMIMEEmail 发送MIME格式邮件（支持附件）
func (c *OutboundClient) SendMIMEEmail(from, to, mimeContent string) error {
	// 验证发件人是否为本域名邮箱
	if !c.isLocalEmail(from) {
		return fmt.Errorf("发件人必须是本域名邮箱: %s", from)
	}

	// 提取收件人域名
	toDomain := extractDomain(to)
	if toDomain == "" {
		return fmt.Errorf("无效的收件人邮箱地址: %s", to)
	}

	log.Printf("开始MX直接发送MIME邮件: %s -> %s", from, to)

	// 检查是否为本地域名，如果是，使用本地MX服务器
	if c.isLocalDomain(toDomain) {
		return c.sendMIMEToLocalMX(from, to, mimeContent)
	}

	// 外部域名，通过MX记录发送
	return c.sendMIMEToExternalMX(from, to, toDomain, mimeContent)
}

// sendMIMEToLocalMX 发送MIME邮件到本地MX服务器
func (c *OutboundClient) sendMIMEToLocalMX(from, to, mimeContent string) error {
	fromDomain := extractDomain(from)
	localDomain := c.getDomainForSender(fromDomain)

	log.Printf("本地域名邮件，使用本地MX服务器: %s (域名: %s)", extractDomain(to), localDomain)
	log.Printf("尝试连接本地MX服务器: 127.0.0.1:25")

	// 连接本地SMTP服务器
	conn, err := net.Dial("tcp", "127.0.0.1:25")
	if err != nil {
		return fmt.Errorf("连接本地MX服务器失败: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, localDomain)
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %w", err)
	}
	defer client.Quit()

	// 设置发件人
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("设置发件人失败: %w", err)
	}

	// 设置收件人
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("设置收件人失败: %w", err)
	}

	// 发送邮件内容
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("开始发送邮件内容失败: %w", err)
	}

	_, err = w.Write([]byte(mimeContent))
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("完成邮件内容发送失败: %w", err)
	}

	log.Printf("✅ 本地MX发送成功: %s -> %s (通过 %s:25)", from, to, localDomain)
	return nil
}

// sendMIMEToExternalMX 发送MIME邮件到外部MX服务器
func (c *OutboundClient) sendMIMEToExternalMX(from, to, domain, mimeContent string) error {
	// 查询MX记录
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return fmt.Errorf("查询MX记录失败: %w", err)
	}

	if len(mxRecords) == 0 {
		return fmt.Errorf("域名 %s 没有MX记录", domain)
	}

	// 按优先级排序并尝试连接
	for i, mx := range mxRecords {
		log.Printf("使用MX服务器: %s (优先级: %d)", mx.Host, mx.Pref)

		err = c.sendMIMEToMXServer(from, to, mx.Host, mimeContent, i+1)
		if err == nil {
			log.Printf("✅ MX直接发送成功: %s -> %s", from, to)
			return nil
		}

		log.Printf("MX服务器 %s 发送失败: %v", mx.Host, err)
	}

	return fmt.Errorf("所有MX服务器都发送失败")
}

// sendMIMEToMXServer 发送MIME邮件到指定MX服务器
func (c *OutboundClient) sendMIMEToMXServer(from, to, mxHost, mimeContent string, attempt int) error {
	log.Printf("尝试连接MX服务器 %s:25 (第%d次)", mxHost, attempt)

	// 连接MX服务器
	conn, err := net.DialTimeout("tcp", mxHost+":25", 30*time.Second)
	if err != nil {
		return fmt.Errorf("连接MX服务器失败: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %w", err)
	}
	defer client.Quit()

	// 设置发件人
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("设置发件人失败: %w", err)
	}

	// 设置收件人
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("设置收件人失败: %w", err)
	}

	// 发送邮件内容
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("开始发送邮件内容失败: %w", err)
	}

	_, err = w.Write([]byte(mimeContent))
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("完成邮件内容发送失败: %w", err)
	}

	return nil
}




