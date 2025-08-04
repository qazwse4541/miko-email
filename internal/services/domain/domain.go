package domain

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"miko-email/internal/models"
	"miko-email/internal/utils"
	"github.com/miekg/dns"
)

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// GetDomains 获取域名列表
func (s *Service) GetDomains() ([]models.Domain, error) {
	query := `
		SELECT id, name, is_verified, is_active,
		       COALESCE(mx_record, '') as mx_record,
		       COALESCE(a_record, '') as a_record,
		       COALESCE(txt_record, '') as txt_record,
		       COALESCE(spf_record, '') as spf_record,
		       COALESCE(dmarc_record, '') as dmarc_record,
		       COALESCE(dkim_record, '') as dkim_record,
		       COALESCE(ptr_record, '') as ptr_record,
		       COALESCE(sender_verification_status, 'pending') as sender_verification_status,
		       COALESCE(receiver_verification_status, 'pending') as receiver_verification_status,
		       created_at, updated_at
		FROM domains
		ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("查询域名列表失败: %v", err)
	}
	defer rows.Close()

	var domains []models.Domain
	for rows.Next() {
		var domain models.Domain
		var createdAtStr, updatedAtStr string

		err = rows.Scan(&domain.ID, &domain.Name, &domain.IsVerified, &domain.IsActive,
			&domain.MXRecord, &domain.ARecord, &domain.TXTRecord,
			&domain.SPFRecord, &domain.DMARCRecord, &domain.DKIMRecord, &domain.PTRRecord,
			&domain.SenderVerificationStatus, &domain.ReceiverVerificationStatus,
			&createdAtStr, &updatedAtStr)
		if err != nil {
			return nil, fmt.Errorf("扫描域名数据失败: %v", err)
		}

		// 解析时间字符串
		if createdAtStr != "" {
			if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST m=+999999999.999999999", createdAtStr); err == nil {
				domain.CreatedAt = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02 15:04:05", createdAtStr); err == nil {
				domain.CreatedAt = parsedTime
			} else {
				domain.CreatedAt = time.Now()
			}
		} else {
			domain.CreatedAt = time.Now()
		}

		if updatedAtStr != "" {
			if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST m=+999999999.999999999", updatedAtStr); err == nil {
				domain.UpdatedAt = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02 15:04:05", updatedAtStr); err == nil {
				domain.UpdatedAt = parsedTime
			} else {
				domain.UpdatedAt = time.Now()
			}
		} else {
			domain.UpdatedAt = time.Now()
		}

		domains = append(domains, domain)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历域名数据失败: %v", err)
	}

	return domains, nil
}

// CreateDomain 创建域名
func (s *Service) CreateDomain(name, mxRecord, aRecord, txtRecord string) (*models.Domain, error) {
	// 检查域名是否已存在
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM domains WHERE name = ?", name).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, fmt.Errorf("域名已存在")
	}

	// 插入域名
	result, err := s.db.Exec(`
		INSERT INTO domains (name, mx_record, a_record, txt_record, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, name, mxRecord, aRecord, txtRecord, time.Now(), time.Now())

	if err != nil {
		return nil, err
	}

	domainID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	domain := &models.Domain{
		ID:                         int(domainID),
		Name:                       name,
		IsVerified:                 false,
		IsActive:                   true,
		MXRecord:                   mxRecord,
		ARecord:                    aRecord,
		TXTRecord:                  txtRecord,
		SenderVerificationStatus:   "pending",
		ReceiverVerificationStatus: "pending",
		CreatedAt:                  time.Now(),
		UpdatedAt:                  time.Now(),
	}

	return domain, nil
}

// CreateDomainWithAllRecords 创建域名（包含所有DNS记录）
func (s *Service) CreateDomainWithAllRecords(name, mxRecord, aRecord, txtRecord, spfRecord, dmarcRecord, dkimRecord, ptrRecord string) (*models.Domain, error) {
	// 检查域名是否已存在
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM domains WHERE name = ?", name).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, fmt.Errorf("域名已存在")
	}

	// 插入域名
	result, err := s.db.Exec(`
		INSERT INTO domains (name, mx_record, a_record, txt_record, spf_record, dmarc_record, dkim_record, ptr_record, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, name, mxRecord, aRecord, txtRecord, spfRecord, dmarcRecord, dkimRecord, ptrRecord, time.Now(), time.Now())

	if err != nil {
		return nil, err
	}

	domainID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	domain := &models.Domain{
		ID:                         int(domainID),
		Name:                       name,
		IsVerified:                 false,
		IsActive:                   true,
		MXRecord:                   mxRecord,
		ARecord:                    aRecord,
		TXTRecord:                  txtRecord,
		SPFRecord:                  spfRecord,
		DMARCRecord:                dmarcRecord,
		DKIMRecord:                 dkimRecord,
		PTRRecord:                  ptrRecord,
		SenderVerificationStatus:   "pending",
		ReceiverVerificationStatus: "pending",
		CreatedAt:                  time.Now(),
		UpdatedAt:                  time.Now(),
	}

	return domain, nil
}

// CreateDomainSimple 简化创建域名（只需要域名，自动生成所有记录）
func (s *Service) CreateDomainSimple(name string) (*models.Domain, error) {
	// 检查域名是否已存在
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM domains WHERE name = ?", name).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, fmt.Errorf("域名已存在")
	}

	// 获取服务器IP
	serverIP := utils.GetServerIP()

	// 自动生成DNS记录
	mxRecord := name                                    // MX记录指向域名本身
	aRecord := serverIP                                 // A记录指向服务器IP
	txtRecord := fmt.Sprintf("v=spf1 ip4:%s ~all", serverIP) // TXT记录包含SPF
	spfRecord := fmt.Sprintf("v=spf1 ip4:%s ~all", serverIP) // SPF记录
	dmarcRecord := fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:dmarc@%s", name) // DMARC记录
	ptrRecord := name // PTR记录

	// 插入域名
	result, err := s.db.Exec(`
		INSERT INTO domains (name, mx_record, a_record, txt_record, spf_record, dmarc_record, ptr_record, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, name, mxRecord, aRecord, txtRecord, spfRecord, dmarcRecord, ptrRecord, time.Now(), time.Now())

	if err != nil {
		return nil, err
	}

	domainID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	domain := &models.Domain{
		ID:                         int(domainID),
		Name:                       name,
		IsVerified:                 false,
		IsActive:                   true,
		MXRecord:                   mxRecord,
		ARecord:                    aRecord,
		TXTRecord:                  txtRecord,
		SPFRecord:                  spfRecord,
		DMARCRecord:                dmarcRecord,
		PTRRecord:                  ptrRecord,
		SenderVerificationStatus:   "pending",
		ReceiverVerificationStatus: "pending",
		CreatedAt:                  time.Now(),
		UpdatedAt:                  time.Now(),
	}

	return domain, nil
}

// VerifyDomain 验证域名DNS设置
func (s *Service) VerifyDomain(domainID int) (*models.Domain, error) {
	// 获取域名信息
	var domain models.Domain
	query := `
		SELECT id, name, is_verified, is_active,
		       COALESCE(mx_record, '') as mx_record,
		       COALESCE(a_record, '') as a_record,
		       COALESCE(txt_record, '') as txt_record,
		       COALESCE(spf_record, '') as spf_record,
		       COALESCE(dmarc_record, '') as dmarc_record,
		       COALESCE(dkim_record, '') as dkim_record,
		       COALESCE(ptr_record, '') as ptr_record,
		       COALESCE(sender_verification_status, 'pending') as sender_verification_status,
		       COALESCE(receiver_verification_status, 'pending') as receiver_verification_status,
		       created_at, updated_at
		FROM domains
		WHERE id = ?
	`

	var createdAtStr, updatedAtStr string
	err := s.db.QueryRow(query, domainID).Scan(
		&domain.ID, &domain.Name, &domain.IsVerified, &domain.IsActive,
		&domain.MXRecord, &domain.ARecord, &domain.TXTRecord,
		&domain.SPFRecord, &domain.DMARCRecord, &domain.DKIMRecord, &domain.PTRRecord,
		&domain.SenderVerificationStatus, &domain.ReceiverVerificationStatus,
		&createdAtStr, &updatedAtStr,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("域名不存在")
		}
		return nil, fmt.Errorf("查询域名失败: %v", err)
	}

	// 解析时间字符串
	if createdAtStr != "" {
		if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST m=+999999999.999999999", createdAtStr); err == nil {
			domain.CreatedAt = parsedTime
		} else if parsedTime, err := time.Parse("2006-01-02 15:04:05", createdAtStr); err == nil {
			domain.CreatedAt = parsedTime
		} else {
			domain.CreatedAt = time.Now()
		}
	} else {
		domain.CreatedAt = time.Now()
	}

	if updatedAtStr != "" {
		if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST m=+999999999.999999999", updatedAtStr); err == nil {
			domain.UpdatedAt = parsedTime
		} else if parsedTime, err := time.Parse("2006-01-02 15:04:05", updatedAtStr); err == nil {
			domain.UpdatedAt = parsedTime
		} else {
			domain.UpdatedAt = time.Now()
		}
	} else {
		domain.UpdatedAt = time.Now()
	}

	// 验证DNS记录
	verified := true

	// 验证MX记录
	if domain.MXRecord != "" {
		if !s.verifyMXRecord(domain.Name, domain.MXRecord) {
			verified = false
		}
	}

	// 验证A记录
	if domain.ARecord != "" {
		if !s.verifyARecord(domain.Name, domain.ARecord) {
			verified = false
		}
	}

	// 验证TXT记录
	if domain.TXTRecord != "" {
		if !s.verifyTXTRecord(domain.Name, domain.TXTRecord) {
			verified = false
		}
	}

	// 更新验证状态
	_, err = s.db.Exec("UPDATE domains SET is_verified = ?, updated_at = ? WHERE id = ?",
		verified, time.Now(), domainID)
	if err != nil {
		return nil, err
	}

	domain.IsVerified = verified
	domain.UpdatedAt = time.Now()

	return &domain, nil
}

// VerifySenderConfiguration 验证发件配置
func (s *Service) VerifySenderConfiguration(domainID int) (*models.Domain, error) {
	// 获取域名信息
	domain, err := s.GetDomainByID(domainID)
	if err != nil {
		return nil, err
	}

	senderStatus := "verified"

	// 验证SPF记录
	if domain.SPFRecord != "" {
		if !s.verifySPFRecord(domain.Name, domain.SPFRecord) {
			senderStatus = "failed"
		}
	}

	// 验证DKIM记录
	if domain.DKIMRecord != "" {
		if !s.verifyDKIMRecord(domain.Name, domain.DKIMRecord) {
			senderStatus = "failed"
		}
	}

	// 验证DMARC记录
	if domain.DMARCRecord != "" {
		if !s.verifyDMARCRecord(domain.Name, domain.DMARCRecord) {
			senderStatus = "failed"
		}
	}

	// 更新发件验证状态
	_, err = s.db.Exec("UPDATE domains SET sender_verification_status = ?, updated_at = ? WHERE id = ?",
		senderStatus, time.Now(), domainID)
	if err != nil {
		return nil, err
	}

	domain.SenderVerificationStatus = senderStatus
	domain.UpdatedAt = time.Now()

	return domain, nil
}

// VerifyReceiverConfiguration 验证收件配置
func (s *Service) VerifyReceiverConfiguration(domainID int) (*models.Domain, error) {
	// 获取域名信息
	domain, err := s.GetDomainByID(domainID)
	if err != nil {
		return nil, err
	}

	receiverStatus := "verified"

	// 验证MX记录
	if domain.MXRecord != "" {
		if !s.verifyMXRecord(domain.Name, domain.MXRecord) {
			receiverStatus = "failed"
		}
	}

	// 验证A记录
	if domain.ARecord != "" {
		if !s.verifyARecord(domain.Name, domain.ARecord) {
			receiverStatus = "failed"
		}
	}

	// 验证PTR记录
	if domain.PTRRecord != "" {
		if !s.verifyPTRRecord(domain.ARecord, domain.PTRRecord) {
			receiverStatus = "failed"
		}
	}

	// 更新收件验证状态
	_, err = s.db.Exec("UPDATE domains SET receiver_verification_status = ?, updated_at = ? WHERE id = ?",
		receiverStatus, time.Now(), domainID)
	if err != nil {
		return nil, err
	}

	domain.ReceiverVerificationStatus = receiverStatus
	domain.UpdatedAt = time.Now()

	return domain, nil
}

// verifyMXRecord 验证MX记录
func (s *Service) verifyMXRecord(domain, expectedMX string) bool {
	// 使用标准库验证
	mxRecords, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxRecords {
			if strings.TrimSuffix(mx.Host, ".") == strings.TrimSuffix(expectedMX, ".") {
				return true
			}
		}
	}

	// 使用DNS库进行更详细的验证
	return s.verifyDNSRecord(domain, dns.TypeMX, expectedMX)
}

// verifyARecord 验证A记录
func (s *Service) verifyARecord(domain, expectedIP string) bool {
	// 使用标准库验证
	ips, err := net.LookupIP(domain)
	if err == nil {
		for _, ip := range ips {
			if ip.String() == expectedIP {
				return true
			}
		}
	}

	// 使用DNS库进行更详细的验证
	return s.verifyDNSRecord(domain, dns.TypeA, expectedIP)
}

// verifyTXTRecord 验证TXT记录
func (s *Service) verifyTXTRecord(domain, expectedTXT string) bool {
	// 使用标准库验证
	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		for _, txt := range txtRecords {
			if txt == expectedTXT {
				return true
			}
		}
	}

	// 使用DNS库进行更详细的验证
	return s.verifyDNSRecord(domain, dns.TypeTXT, expectedTXT)
}

// verifyDNSRecord 使用DNS库验证DNS记录
func (s *Service) verifyDNSRecord(domain string, recordType uint16, expectedValue string) bool {
	c := dns.Client{
		Timeout: time.Second * 5,
	}

	// 构造DNS查询
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), recordType)

	// 查询DNS服务器
	dnsServers := []string{"8.8.8.8:53", "1.1.1.1:53", "114.114.114.114:53"}

	for _, server := range dnsServers {
		r, _, err := c.Exchange(&m, server)
		if err != nil {
			continue
		}

		// 检查响应
		for _, ans := range r.Answer {
			switch recordType {
			case dns.TypeMX:
				if mx, ok := ans.(*dns.MX); ok {
					if strings.TrimSuffix(mx.Mx, ".") == strings.TrimSuffix(expectedValue, ".") {
						return true
					}
				}
			case dns.TypeA:
				if a, ok := ans.(*dns.A); ok {
					if a.A.String() == expectedValue {
						return true
					}
				}
			case dns.TypeTXT:
				if txt, ok := ans.(*dns.TXT); ok {
					for _, t := range txt.Txt {
						if t == expectedValue {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// verifySPFRecord 验证SPF记录
func (s *Service) verifySPFRecord(domain, expectedSPF string) bool {
	// SPF记录通常在TXT记录中
	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		for _, txt := range txtRecords {
			if strings.HasPrefix(txt, "v=spf1") && strings.Contains(txt, expectedSPF) {
				return true
			}
		}
	}
	return s.verifyDNSRecord(domain, dns.TypeTXT, expectedSPF)
}

// verifyDMARCRecord 验证DMARC记录
func (s *Service) verifyDMARCRecord(domain, expectedDMARC string) bool {
	// DMARC记录在_dmarc子域名的TXT记录中
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err == nil {
		for _, txt := range txtRecords {
			if strings.HasPrefix(txt, "v=DMARC1") && strings.Contains(txt, expectedDMARC) {
				return true
			}
		}
	}
	return s.verifyDNSRecord(dmarcDomain, dns.TypeTXT, expectedDMARC)
}

// verifyDKIMRecord 验证DKIM记录
func (s *Service) verifyDKIMRecord(domain, expectedDKIM string) bool {
	// DKIM记录通常在selector._domainkey.domain的TXT记录中
	// 这里假设使用default作为selector
	dkimDomain := "default._domainkey." + domain
	txtRecords, err := net.LookupTXT(dkimDomain)
	if err == nil {
		for _, txt := range txtRecords {
			if strings.Contains(txt, "v=DKIM1") && strings.Contains(txt, expectedDKIM) {
				return true
			}
		}
	}
	return s.verifyDNSRecord(dkimDomain, dns.TypeTXT, expectedDKIM)
}

// verifyPTRRecord 验证PTR记录
func (s *Service) verifyPTRRecord(ip, expectedPTR string) bool {
	// 反向DNS查询
	names, err := net.LookupAddr(ip)
	if err == nil {
		for _, name := range names {
			if strings.TrimSuffix(name, ".") == strings.TrimSuffix(expectedPTR, ".") {
				return true
			}
		}
	}
	return false
}

// GetDNSRecords 获取域名的所有DNS记录信息
func (s *Service) GetDNSRecords(domain string) map[string][]string {
	records := make(map[string][]string)

	// 获取MX记录
	if mxRecords, err := net.LookupMX(domain); err == nil {
		var mxList []string
		for _, mx := range mxRecords {
			mxList = append(mxList, fmt.Sprintf("%s (优先级: %d)", strings.TrimSuffix(mx.Host, "."), mx.Pref))
		}
		records["MX"] = mxList
	}

	// 获取A记录
	if ips, err := net.LookupIP(domain); err == nil {
		var aList []string
		for _, ip := range ips {
			if ip.To4() != nil { // 只获取IPv4地址
				aList = append(aList, ip.String())
			}
		}
		records["A"] = aList
	}

	// 获取TXT记录
	if txtRecords, err := net.LookupTXT(domain); err == nil {
		records["TXT"] = txtRecords
	}

	// 获取CNAME记录
	if cname, err := net.LookupCNAME(domain); err == nil && cname != domain+"." {
		records["CNAME"] = []string{strings.TrimSuffix(cname, ".")}
	}

	return records
}

// VerifySingleDNSRecord 验证单个DNS记录
func (s *Service) VerifySingleDNSRecord(domain, recordType, expectedValue string) (bool, string, error) {
	switch strings.ToUpper(recordType) {
	case "MX":
		if s.verifyMXRecord(domain, expectedValue) {
			return true, "MX记录验证成功", nil
		}
		return false, "MX记录验证失败，DNS中未找到匹配的记录", nil
	case "A":
		if s.verifyARecord(domain, expectedValue) {
			return true, "A记录验证成功", nil
		}
		return false, "A记录验证失败，DNS中未找到匹配的记录", nil
	case "TXT":
		if s.verifyTXTRecord(domain, expectedValue) {
			return true, "TXT记录验证成功", nil
		}
		return false, "TXT记录验证失败，DNS中未找到匹配的记录", nil
	case "SPF":
		if s.verifySPFRecord(domain, expectedValue) {
			return true, "SPF记录验证成功", nil
		}
		return false, "SPF记录验证失败，DNS中未找到匹配的记录", nil
	case "DKIM":
		if s.verifyDKIMRecord(domain, expectedValue) {
			return true, "DKIM记录验证成功", nil
		}
		return false, "DKIM记录验证失败，DNS中未找到匹配的记录", nil
	case "DMARC":
		if s.verifyDMARCRecord(domain, expectedValue) {
			return true, "DMARC记录验证成功", nil
		}
		return false, "DMARC记录验证失败，DNS中未找到匹配的记录", nil
	case "PTR":
		// PTR记录需要IP地址作为查询参数
		if s.verifyPTRRecord(expectedValue, domain) {
			return true, "PTR记录验证成功", nil
		}
		return false, "PTR记录验证失败，反向DNS查询未找到匹配的记录", nil
	default:
		return false, "", fmt.Errorf("不支持的记录类型: %s", recordType)
	}
}

// GetDomainByID 根据ID获取域名
func (s *Service) GetDomainByID(domainID int) (*models.Domain, error) {
	var domain models.Domain
	query := `
		SELECT id, name, is_verified, is_active,
		       COALESCE(mx_record, '') as mx_record,
		       COALESCE(a_record, '') as a_record,
		       COALESCE(txt_record, '') as txt_record,
		       COALESCE(spf_record, '') as spf_record,
		       COALESCE(dmarc_record, '') as dmarc_record,
		       COALESCE(dkim_record, '') as dkim_record,
		       COALESCE(ptr_record, '') as ptr_record,
		       COALESCE(sender_verification_status, 'pending') as sender_verification_status,
		       COALESCE(receiver_verification_status, 'pending') as receiver_verification_status,
		       created_at, updated_at
		FROM domains
		WHERE id = ?
	`

	var createdAtStr, updatedAtStr string
	err := s.db.QueryRow(query, domainID).Scan(
		&domain.ID, &domain.Name, &domain.IsVerified, &domain.IsActive,
		&domain.MXRecord, &domain.ARecord, &domain.TXTRecord,
		&domain.SPFRecord, &domain.DMARCRecord, &domain.DKIMRecord, &domain.PTRRecord,
		&domain.SenderVerificationStatus, &domain.ReceiverVerificationStatus,
		&createdAtStr, &updatedAtStr,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("域名不存在")
		}
		return nil, fmt.Errorf("查询域名失败: %v", err)
	}

	// 解析时间字符串
	if createdAtStr != "" {
		if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST m=+999999999.999999999", createdAtStr); err == nil {
			domain.CreatedAt = parsedTime
		} else if parsedTime, err := time.Parse("2006-01-02 15:04:05", createdAtStr); err == nil {
			domain.CreatedAt = parsedTime
		} else {
			domain.CreatedAt = time.Now()
		}
	} else {
		domain.CreatedAt = time.Now()
	}

	if updatedAtStr != "" {
		if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST m=+999999999.999999999", updatedAtStr); err == nil {
			domain.UpdatedAt = parsedTime
		} else if parsedTime, err := time.Parse("2006-01-02 15:04:05", updatedAtStr); err == nil {
			domain.UpdatedAt = parsedTime
		} else {
			domain.UpdatedAt = time.Now()
		}
	} else {
		domain.UpdatedAt = time.Now()
	}

	return &domain, nil
}

// UpdateDomain 更新域名信息
func (s *Service) UpdateDomain(domainID int, mxRecord, aRecord, txtRecord string) error {
	_, err := s.db.Exec(`
		UPDATE domains
		SET mx_record = ?, a_record = ?, txt_record = ?, updated_at = ?
		WHERE id = ?
	`, mxRecord, aRecord, txtRecord, time.Now(), domainID)

	return err
}

// UpdateDomainWithAllRecords 更新域名信息（包含所有DNS记录）
func (s *Service) UpdateDomainWithAllRecords(domainID int, mxRecord, aRecord, txtRecord, spfRecord, dmarcRecord, dkimRecord, ptrRecord string) error {
	_, err := s.db.Exec(`
		UPDATE domains
		SET mx_record = ?, a_record = ?, txt_record = ?, spf_record = ?, dmarc_record = ?, dkim_record = ?, ptr_record = ?, updated_at = ?
		WHERE id = ?
	`, mxRecord, aRecord, txtRecord, spfRecord, dmarcRecord, dkimRecord, ptrRecord, time.Now(), domainID)

	return err
}

// DeleteDomain 删除域名
func (s *Service) DeleteDomain(domainID int) error {
	// 检查是否有邮箱使用此域名
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM mailboxes WHERE domain_id = ? AND is_active = 1", domainID).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("该域名下还有邮箱，无法删除")
	}

	// 真正删除域名记录
	_, err = s.db.Exec("DELETE FROM domains WHERE id = ?", domainID)
	return err
}

// GetAvailableDomains 获取可用的域名列表（激活的域名，用于用户注册）
func (s *Service) GetAvailableDomains() ([]models.Domain, error) {
	query := `
		SELECT id, name, is_verified, is_active,
		       COALESCE(mx_record, '') as mx_record,
		       COALESCE(a_record, '') as a_record,
		       COALESCE(txt_record, '') as txt_record,
		       COALESCE(spf_record, '') as spf_record,
		       COALESCE(dmarc_record, '') as dmarc_record,
		       COALESCE(dkim_record, '') as dkim_record,
		       COALESCE(ptr_record, '') as ptr_record,
		       COALESCE(sender_verification_status, 'pending') as sender_verification_status,
		       COALESCE(receiver_verification_status, 'pending') as receiver_verification_status,
		       created_at, updated_at
		FROM domains
		WHERE is_active = 1 AND is_verified = 1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("查询可用域名列表失败: %v", err)
	}
	defer rows.Close()

	var domains []models.Domain
	for rows.Next() {
		var domain models.Domain
		var createdAtStr, updatedAtStr string

		err = rows.Scan(&domain.ID, &domain.Name, &domain.IsVerified, &domain.IsActive,
			&domain.MXRecord, &domain.ARecord, &domain.TXTRecord,
			&domain.SPFRecord, &domain.DMARCRecord, &domain.DKIMRecord, &domain.PTRRecord,
			&domain.SenderVerificationStatus, &domain.ReceiverVerificationStatus,
			&createdAtStr, &updatedAtStr)
		if err != nil {
			return nil, fmt.Errorf("扫描可用域名数据失败: %v", err)
		}

		// 解析时间字符串
		if createdAtStr != "" {
			if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST m=+999999999.999999999", createdAtStr); err == nil {
				domain.CreatedAt = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02 15:04:05", createdAtStr); err == nil {
				domain.CreatedAt = parsedTime
			} else {
				domain.CreatedAt = time.Now()
			}
		} else {
			domain.CreatedAt = time.Now()
		}

		if updatedAtStr != "" {
			if parsedTime, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST m=+999999999.999999999", updatedAtStr); err == nil {
				domain.UpdatedAt = parsedTime
			} else if parsedTime, err := time.Parse("2006-01-02 15:04:05", updatedAtStr); err == nil {
				domain.UpdatedAt = parsedTime
			} else {
				domain.UpdatedAt = time.Now()
			}
		} else {
			domain.UpdatedAt = time.Now()
		}

		domains = append(domains, domain)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历可用域名数据失败: %v", err)
	}

	return domains, nil
}
