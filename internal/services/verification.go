package services

import (
	"database/sql"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"
	"time"

	"miko-email/internal/models"
)

type VerificationService struct {
	db *sql.DB
}

func NewVerificationService(db *sql.DB) *VerificationService {
	return &VerificationService{db: db}
}

// InitDefaultRules 初始化默认验证码规则
func (s *VerificationService) InitDefaultRules() error {
	// 检查是否已经初始化过
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM verification_rules WHERE type = 'default'").Scan(&count)
	if err != nil {
		return fmt.Errorf("检查默认规则失败: %v", err)
	}

	if count > 0 {
		return nil // 已经初始化过
	}

	// 插入默认规则
	for _, rule := range models.DefaultVerificationRules {
		_, err := s.db.Exec(`
			INSERT INTO verification_rules (name, description, pattern, type, priority, enabled, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, rule.Name, rule.Description, rule.Pattern, rule.Type, rule.Priority, rule.Enabled, time.Now(), time.Now())
		
		if err != nil {
			return fmt.Errorf("插入默认规则失败: %v", err)
		}
	}

	return nil
}

// GetRules 获取所有验证码规则
func (s *VerificationService) GetRules() ([]models.VerificationRule, error) {
	rows, err := s.db.Query(`
		SELECT id, name, description, pattern, type, priority, enabled, created_at, updated_at
		FROM verification_rules
		ORDER BY priority ASC, created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("查询验证码规则失败: %v", err)
	}
	defer rows.Close()

	var rules []models.VerificationRule
	for rows.Next() {
		var rule models.VerificationRule
		err := rows.Scan(&rule.ID, &rule.Name, &rule.Description, &rule.Pattern, 
			&rule.Type, &rule.Priority, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("扫描验证码规则失败: %v", err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// GetEnabledRules 获取启用的验证码规则
func (s *VerificationService) GetEnabledRules() ([]models.VerificationRule, error) {
	rows, err := s.db.Query(`
		SELECT id, name, description, pattern, type, priority, enabled, created_at, updated_at
		FROM verification_rules
		WHERE enabled = 1
		ORDER BY priority ASC, created_at ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("查询启用的验证码规则失败: %v", err)
	}
	defer rows.Close()

	var rules []models.VerificationRule
	for rows.Next() {
		var rule models.VerificationRule
		err := rows.Scan(&rule.ID, &rule.Name, &rule.Description, &rule.Pattern, 
			&rule.Type, &rule.Priority, &rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("扫描验证码规则失败: %v", err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// CreateRule 创建验证码规则
func (s *VerificationService) CreateRule(rule *models.VerificationRule) error {
	// 验证正则表达式
	_, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return fmt.Errorf("无效的正则表达式: %v", err)
	}

	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	result, err := s.db.Exec(`
		INSERT INTO verification_rules (name, description, pattern, type, priority, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, rule.Name, rule.Description, rule.Pattern, rule.Type, rule.Priority, rule.Enabled, rule.CreatedAt, rule.UpdatedAt)
	
	if err != nil {
		return fmt.Errorf("创建验证码规则失败: %v", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("获取规则ID失败: %v", err)
	}

	rule.ID = int(id)
	return nil
}

// UpdateRule 更新验证码规则
func (s *VerificationService) UpdateRule(rule *models.VerificationRule) error {
	// 验证正则表达式
	_, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return fmt.Errorf("无效的正则表达式: %v", err)
	}

	rule.UpdatedAt = time.Now()

	_, err = s.db.Exec(`
		UPDATE verification_rules 
		SET name = ?, description = ?, pattern = ?, type = ?, priority = ?, enabled = ?, updated_at = ?
		WHERE id = ?
	`, rule.Name, rule.Description, rule.Pattern, rule.Type, rule.Priority, rule.Enabled, rule.UpdatedAt, rule.ID)
	
	if err != nil {
		return fmt.Errorf("更新验证码规则失败: %v", err)
	}

	return nil
}

// DeleteRule 删除验证码规则
func (s *VerificationService) DeleteRule(id int) error {
	_, err := s.db.Exec("DELETE FROM verification_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("删除验证码规则失败: %v", err)
	}
	return nil
}

// htmlToText 将HTML内容转换为纯文本
func htmlToText(htmlContent string) string {
	// 首先移除不应该显示的标签内容
	cleanHtml := htmlContent

	// 移除style标签及其内容
	styleRe := regexp.MustCompile(`(?i)<style[^>]*>[\s\S]*?</style>`)
	cleanHtml = styleRe.ReplaceAllString(cleanHtml, "")

	// 移除script标签及其内容
	scriptRe := regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?</script>`)
	cleanHtml = scriptRe.ReplaceAllString(cleanHtml, "")

	// 移除注释
	commentRe := regexp.MustCompile(`<!--[\s\S]*?-->`)
	cleanHtml = commentRe.ReplaceAllString(cleanHtml, "")

	// 移除head标签及其内容
	headRe := regexp.MustCompile(`(?i)<head[^>]*>[\s\S]*?</head>`)
	cleanHtml = headRe.ReplaceAllString(cleanHtml, "")

	// 移除HTML标签
	tagRe := regexp.MustCompile(`<[^>]*>`)
	text := tagRe.ReplaceAllString(cleanHtml, " ")

	// 解码HTML实体
	text = html.UnescapeString(text)

	// 清理多余的空白字符
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	text = strings.TrimSpace(text)

	return text
}

// ExtractVerificationCodes 从邮件内容中提取验证码
func (s *VerificationService) ExtractVerificationCodes(content string) ([]models.ExtractedCode, error) {
	rules, err := s.GetEnabledRules()
	if err != nil {
		return nil, fmt.Errorf("获取验证码规则失败: %v", err)
	}

	var extractedCodes []models.ExtractedCode
	usedCodes := make(map[string]bool) // 防止重复提取相同的验证码

	// 按优先级排序规则
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	// 准备要搜索的内容：原始内容和转换后的纯文本
	searchContents := []string{content}

	// 如果内容包含HTML标签，添加纯文本版本
	if strings.Contains(content, "<") && strings.Contains(content, ">") {
		plainText := htmlToText(content)
		searchContents = append(searchContents, plainText)
	}

	for _, rule := range rules {
		regex, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue // 跳过无效的正则表达式
		}

		// 在所有版本的内容中搜索
		for _, searchContent := range searchContents {
			matches := regex.FindAllStringSubmatch(searchContent, -1)
			for _, match := range matches {
				if len(match) > 1 {
					code := strings.TrimSpace(match[1])
					if code != "" && !usedCodes[code] {
						extractedCodes = append(extractedCodes, models.ExtractedCode{
							Code:        code,
							Pattern:     rule.Pattern,
							RuleName:    rule.Name,
							MatchedText: match[0],
							Position:    strings.Index(searchContent, match[0]),
						})
						usedCodes[code] = true
					}
				}
			}
		}
	}

	return extractedCodes, nil
}

// TestRule 测试验证码规则
func (s *VerificationService) TestRule(pattern, testContent string) ([]models.ExtractedCode, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("无效的正则表达式: %v", err)
	}

	var extractedCodes []models.ExtractedCode

	// 准备要搜索的内容：原始内容和转换后的纯文本
	searchContents := []string{testContent}

	// 如果内容包含HTML标签，添加纯文本版本
	if strings.Contains(testContent, "<") && strings.Contains(testContent, ">") {
		plainText := htmlToText(testContent)
		searchContents = append(searchContents, plainText)
		// 添加调试信息
		fmt.Printf("DEBUG: 原始内容长度: %d, 转换后长度: %d\n", len(testContent), len(plainText))
		fmt.Printf("DEBUG: 转换后内容前200字符: %s\n", plainText[:min(200, len(plainText))])
	}

	// 在所有版本的内容中搜索
	for i, searchContent := range searchContents {
		fmt.Printf("DEBUG: 在内容版本 %d 中搜索，长度: %d\n", i+1, len(searchContent))
		matches := regex.FindAllStringSubmatch(searchContent, -1)
		fmt.Printf("DEBUG: 找到 %d 个匹配\n", len(matches))

		for _, match := range matches {
			if len(match) > 1 {
				code := strings.TrimSpace(match[1])
				if code != "" {
					extractedCodes = append(extractedCodes, models.ExtractedCode{
						Code:        code,
						Pattern:     pattern,
						RuleName:    "测试规则",
						MatchedText: match[0],
						Position:    strings.Index(searchContent, match[0]),
					})
					fmt.Printf("DEBUG: 提取到验证码: %s\n", code)
				}
			}
		}
	}

	return extractedCodes, nil
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
