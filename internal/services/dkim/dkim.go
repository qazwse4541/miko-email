package dkim

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// Service DKIM服务
type Service struct {
	keyDir string
}

// NewService 创建DKIM服务
func NewService(keyDir string) *Service {
	// 确保密钥目录存在
	os.MkdirAll(keyDir, 0755)
	return &Service{
		keyDir: keyDir,
	}
}

// GenerateKeyPair 为域名生成DKIM密钥对
func (s *Service) GenerateKeyPair(domain string) (string, error) {
	// 生成RSA密钥对
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("生成RSA密钥失败: %v", err)
	}

	// 获取公钥
	publicKey := &privateKey.PublicKey

	// 将公钥转换为PKIX格式
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("序列化公钥失败: %v", err)
	}

	// 将公钥编码为base64
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	// 将私钥转换为PKCS#1格式
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// 创建PEM块
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// 保存私钥到文件
	privateKeyPath := filepath.Join(s.keyDir, fmt.Sprintf("%s.private", domain))
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("创建私钥文件失败: %v", err)
	}
	defer privateKeyFile.Close()

	err = pem.Encode(privateKeyFile, privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("写入私钥文件失败: %v", err)
	}

	// 保存公钥到文件
	publicKeyPath := filepath.Join(s.keyDir, fmt.Sprintf("%s.public", domain))
	publicKeyFile, err := os.Create(publicKeyPath)
	if err != nil {
		return "", fmt.Errorf("创建公钥文件失败: %v", err)
	}
	defer publicKeyFile.Close()

	_, err = publicKeyFile.WriteString(publicKeyBase64)
	if err != nil {
		return "", fmt.Errorf("写入公钥文件失败: %v", err)
	}

	return publicKeyBase64, nil
}

// GetPublicKey 获取域名的DKIM公钥
func (s *Service) GetPublicKey(domain string) (string, error) {
	publicKeyPath := filepath.Join(s.keyDir, fmt.Sprintf("%s.public", domain))
	
	// 检查文件是否存在
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		// 如果不存在，生成新的密钥对
		return s.GenerateKeyPair(domain)
	}

	// 读取公钥文件
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", fmt.Errorf("读取公钥文件失败: %v", err)
	}

	return string(publicKeyBytes), nil
}

// GetPrivateKey 获取域名的DKIM私钥
func (s *Service) GetPrivateKey(domain string) (string, error) {
	privateKeyPath := filepath.Join(s.keyDir, fmt.Sprintf("%s.private", domain))
	
	// 检查文件是否存在
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		return "", fmt.Errorf("私钥文件不存在，请先生成密钥对")
	}

	// 读取私钥文件
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("读取私钥文件失败: %v", err)
	}

	return string(privateKeyBytes), nil
}

// GenerateDKIMRecord 生成DKIM DNS记录
func (s *Service) GenerateDKIMRecord(domain string) (string, error) {
	publicKey, err := s.GetPublicKey(domain)
	if err != nil {
		return "", err
	}

	// 构造DKIM记录
	// 移除换行符和空格
	cleanPublicKey := strings.ReplaceAll(publicKey, "\n", "")
	cleanPublicKey = strings.ReplaceAll(cleanPublicKey, "\r", "")
	cleanPublicKey = strings.ReplaceAll(cleanPublicKey, " ", "")

	dkimRecord := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", cleanPublicKey)
	
	return dkimRecord, nil
}

// GetDKIMSelector 获取DKIM选择器（默认使用"default"）
func (s *Service) GetDKIMSelector() string {
	return "default"
}

// GetDKIMDomain 获取DKIM域名
func (s *Service) GetDKIMDomain(domain string) string {
	return fmt.Sprintf("%s._domainkey.%s", s.GetDKIMSelector(), domain)
}

// ListDomainKeys 列出所有域名的密钥
func (s *Service) ListDomainKeys() ([]string, error) {
	files, err := os.ReadDir(s.keyDir)
	if err != nil {
		return nil, fmt.Errorf("读取密钥目录失败: %v", err)
	}

	var domains []string
	domainSet := make(map[string]bool)

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		if strings.HasSuffix(name, ".private") || strings.HasSuffix(name, ".public") {
			domain := strings.TrimSuffix(name, ".private")
			domain = strings.TrimSuffix(domain, ".public")
			if !domainSet[domain] {
				domains = append(domains, domain)
				domainSet[domain] = true
			}
		}
	}

	return domains, nil
}

// DeleteDomainKeys 删除域名的密钥文件
func (s *Service) DeleteDomainKeys(domain string) error {
	privateKeyPath := filepath.Join(s.keyDir, fmt.Sprintf("%s.private", domain))
	publicKeyPath := filepath.Join(s.keyDir, fmt.Sprintf("%s.public", domain))

	// 删除私钥文件
	if _, err := os.Stat(privateKeyPath); err == nil {
		if err := os.Remove(privateKeyPath); err != nil {
			return fmt.Errorf("删除私钥文件失败: %v", err)
		}
	}

	// 删除公钥文件
	if _, err := os.Stat(publicKeyPath); err == nil {
		if err := os.Remove(publicKeyPath); err != nil {
			return fmt.Errorf("删除公钥文件失败: %v", err)
		}
	}

	return nil
}

// SignEmail 对邮件进行DKIM签名
func (s *Service) SignEmail(domain, selector string, emailContent []byte) ([]byte, error) {
	// 获取私钥
	privateKeyPEM, err := s.GetPrivateKey(domain)
	if err != nil {
		return nil, fmt.Errorf("获取私钥失败: %v", err)
	}

	// 解析私钥
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("解析私钥PEM失败")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %v", err)
	}

	// 创建DKIM签名选项
	options := &dkim.SignOptions{
		Domain:   domain,
		Selector: selector,
		Signer:   privateKey,
		HeaderKeys: []string{
			"from", "to", "subject", "date", "message-id",
		},
		Expiration: time.Now().Add(24 * time.Hour), // 24小时后过期
	}

	// 对邮件进行签名
	var signedEmail bytes.Buffer
	if err := dkim.Sign(&signedEmail, bytes.NewReader(emailContent), options); err != nil {
		return nil, fmt.Errorf("DKIM签名失败: %v", err)
	}

	return signedEmail.Bytes(), nil
}
