package global_forward

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"
)

// Service 全局转发服务
type Service struct {
	db *sql.DB
}

// NewService 创建全局转发服务
func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// GlobalForwardRule 全局转发规则结构
type GlobalForwardRule struct {
	ID                 int        `json:"id"`
	UserID             int        `json:"user_id"`
	Name               string     `json:"name"`
	SourcePattern      string     `json:"source_pattern"`
	TargetEmail        string     `json:"target_email"`
	Enabled            bool       `json:"enabled"`
	KeepOriginal       bool       `json:"keep_original"`
	ForwardAttachments bool       `json:"forward_attachments"`
	SubjectPrefix      string     `json:"subject_prefix"`
	Description        string     `json:"description"`
	Priority           int        `json:"priority"`
	ForwardCount       int        `json:"forward_count"`
	LastForwardAt      *time.Time `json:"last_forward_at"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// CreateGlobalForwardRuleRequest 创建全局转发规则请求
type CreateGlobalForwardRuleRequest struct {
	Name               string `json:"name" binding:"required"`
	SourcePattern      string `json:"source_pattern" binding:"required"`
	TargetEmail        string `json:"target_email" binding:"required,email"`
	Enabled            bool   `json:"enabled"`
	KeepOriginal       bool   `json:"keep_original"`
	ForwardAttachments bool   `json:"forward_attachments"`
	SubjectPrefix      string `json:"subject_prefix"`
	Description        string `json:"description"`
	Priority           int    `json:"priority"`
}

// UpdateGlobalForwardRuleRequest 更新全局转发规则请求
type UpdateGlobalForwardRuleRequest struct {
	Name               string `json:"name" binding:"required"`
	SourcePattern      string `json:"source_pattern" binding:"required"`
	TargetEmail        string `json:"target_email" binding:"required,email"`
	Enabled            bool   `json:"enabled"`
	KeepOriginal       bool   `json:"keep_original"`
	ForwardAttachments bool   `json:"forward_attachments"`
	SubjectPrefix      string `json:"subject_prefix"`
	Description        string `json:"description"`
	Priority           int    `json:"priority"`
}

// GetGlobalForwardRulesByUser 获取用户的全局转发规则
func (s *Service) GetGlobalForwardRulesByUser(userID int) ([]*GlobalForwardRule, error) {
	query := `
		SELECT id, user_id, name, source_pattern, target_email, enabled, 
		       keep_original, forward_attachments, subject_prefix, description, 
		       priority, forward_count, last_forward_at, created_at, updated_at
		FROM global_forward_rules 
		WHERE user_id = ? 
		ORDER BY priority DESC, created_at DESC
	`
	
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("查询全局转发规则失败: %w", err)
	}
	defer rows.Close()

	var rules []*GlobalForwardRule
	for rows.Next() {
		rule := &GlobalForwardRule{}
		err := rows.Scan(
			&rule.ID, &rule.UserID, &rule.Name, &rule.SourcePattern, &rule.TargetEmail,
			&rule.Enabled, &rule.KeepOriginal, &rule.ForwardAttachments, &rule.SubjectPrefix,
			&rule.Description, &rule.Priority, &rule.ForwardCount, &rule.LastForwardAt,
			&rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("扫描全局转发规则失败: %w", err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// GetGlobalForwardRuleByID 根据ID获取全局转发规则
func (s *Service) GetGlobalForwardRuleByID(ruleID, userID int) (*GlobalForwardRule, error) {
	query := `
		SELECT id, user_id, name, source_pattern, target_email, enabled, 
		       keep_original, forward_attachments, subject_prefix, description, 
		       priority, forward_count, last_forward_at, created_at, updated_at
		FROM global_forward_rules 
		WHERE id = ? AND user_id = ?
	`
	
	rule := &GlobalForwardRule{}
	err := s.db.QueryRow(query, ruleID, userID).Scan(
		&rule.ID, &rule.UserID, &rule.Name, &rule.SourcePattern, &rule.TargetEmail,
		&rule.Enabled, &rule.KeepOriginal, &rule.ForwardAttachments, &rule.SubjectPrefix,
		&rule.Description, &rule.Priority, &rule.ForwardCount, &rule.LastForwardAt,
		&rule.CreatedAt, &rule.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("全局转发规则不存在")
		}
		return nil, fmt.Errorf("查询全局转发规则失败: %w", err)
	}

	return rule, nil
}

// CreateGlobalForwardRule 创建全局转发规则
func (s *Service) CreateGlobalForwardRule(userID int, req CreateGlobalForwardRuleRequest) (*GlobalForwardRule, error) {
	// 检查是否已存在相同的规则
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM global_forward_rules WHERE user_id = ? AND source_pattern = ? AND target_email = ?", 
		userID, req.SourcePattern, req.TargetEmail).Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("检查全局转发规则失败: %w", err)
	}
	if count > 0 {
		return nil, fmt.Errorf("相同的全局转发规则已存在")
	}

	// 创建全局转发规则
	now := time.Now()
	result, err := s.db.Exec(`
		INSERT INTO global_forward_rules (user_id, name, source_pattern, target_email, enabled, 
		                                 keep_original, forward_attachments, subject_prefix, 
		                                 description, priority, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, userID, req.Name, req.SourcePattern, req.TargetEmail, req.Enabled, 
	   req.KeepOriginal, req.ForwardAttachments, req.SubjectPrefix, 
	   req.Description, req.Priority, now, now)

	if err != nil {
		return nil, fmt.Errorf("创建全局转发规则失败: %w", err)
	}

	ruleID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("获取全局转发规则ID失败: %w", err)
	}

	// 返回创建的规则
	return s.GetGlobalForwardRuleByID(int(ruleID), userID)
}

// UpdateGlobalForwardRule 更新全局转发规则
func (s *Service) UpdateGlobalForwardRule(ruleID, userID int, req UpdateGlobalForwardRuleRequest) error {
	// 检查规则是否存在且属于当前用户
	_, err := s.GetGlobalForwardRuleByID(ruleID, userID)
	if err != nil {
		return err
	}

	// 更新全局转发规则
	_, err = s.db.Exec(`
		UPDATE global_forward_rules 
		SET name = ?, source_pattern = ?, target_email = ?, enabled = ?, 
		    keep_original = ?, forward_attachments = ?, subject_prefix = ?, 
		    description = ?, priority = ?, updated_at = ?
		WHERE id = ? AND user_id = ?
	`, req.Name, req.SourcePattern, req.TargetEmail, req.Enabled, 
	   req.KeepOriginal, req.ForwardAttachments, req.SubjectPrefix, 
	   req.Description, req.Priority, time.Now(), ruleID, userID)

	if err != nil {
		return fmt.Errorf("更新全局转发规则失败: %w", err)
	}

	return nil
}

// DeleteGlobalForwardRule 删除全局转发规则
func (s *Service) DeleteGlobalForwardRule(ruleID, userID int) error {
	// 检查规则是否存在且属于当前用户
	_, err := s.GetGlobalForwardRuleByID(ruleID, userID)
	if err != nil {
		return err
	}

	// 删除全局转发规则
	_, err = s.db.Exec("DELETE FROM global_forward_rules WHERE id = ? AND user_id = ?", ruleID, userID)
	if err != nil {
		return fmt.Errorf("删除全局转发规则失败: %w", err)
	}

	return nil
}

// ToggleGlobalForwardRule 切换全局转发规则状态
func (s *Service) ToggleGlobalForwardRule(ruleID, userID int, enabled bool) error {
	// 检查规则是否存在且属于当前用户
	_, err := s.GetGlobalForwardRuleByID(ruleID, userID)
	if err != nil {
		return err
	}

	// 更新状态
	_, err = s.db.Exec("UPDATE global_forward_rules SET enabled = ?, updated_at = ? WHERE id = ? AND user_id = ?", 
		enabled, time.Now(), ruleID, userID)
	if err != nil {
		return fmt.Errorf("更新全局转发规则状态失败: %w", err)
	}

	return nil
}

// GetActiveGlobalForwardRules 获取活跃的全局转发规则（用于邮件处理）
func (s *Service) GetActiveGlobalForwardRules(sourceEmail string) ([]*GlobalForwardRule, error) {
	// 首先获取邮箱对应的用户ID
	var userID int
	err := s.db.QueryRow("SELECT user_id FROM mailboxes WHERE email = ? AND is_active = 1", sourceEmail).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("邮箱 %s 不存在或未激活，跳过全局转发规则检查", sourceEmail)
			return []*GlobalForwardRule{}, nil
		}
		return nil, fmt.Errorf("查询邮箱用户ID失败: %w", err)
	}

	// 只查询该用户创建的活跃全局转发规则
	query := `
		SELECT id, user_id, name, source_pattern, target_email, enabled,
		       keep_original, forward_attachments, subject_prefix, description,
		       priority, forward_count, last_forward_at, created_at, updated_at
		FROM global_forward_rules
		WHERE enabled = 1 AND user_id = ?
		ORDER BY priority DESC, created_at ASC
	`

	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("查询活跃全局转发规则失败: %w", err)
	}
	defer rows.Close()

	var matchedRules []*GlobalForwardRule
	for rows.Next() {
		rule := &GlobalForwardRule{}
		err := rows.Scan(
			&rule.ID, &rule.UserID, &rule.Name, &rule.SourcePattern, &rule.TargetEmail,
			&rule.Enabled, &rule.KeepOriginal, &rule.ForwardAttachments, &rule.SubjectPrefix,
			&rule.Description, &rule.Priority, &rule.ForwardCount, &rule.LastForwardAt,
			&rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			log.Printf("扫描全局转发规则失败: %v", err)
			continue
		}

		// 检查邮箱是否匹配规则
		if s.matchesPattern(sourceEmail, rule.SourcePattern) {
			matchedRules = append(matchedRules, rule)
		}
	}

	return matchedRules, nil
}

// matchesPattern 检查邮箱是否匹配模式
func (s *Service) matchesPattern(email, pattern string) bool {
	// 支持通配符匹配
	if pattern == "*" {
		return true
	}
	
	// 支持域名通配符，如 *@example.com
	if strings.HasPrefix(pattern, "*@") {
		domain := strings.TrimPrefix(pattern, "*@")
		return strings.HasSuffix(email, "@"+domain)
	}
	
	// 支持用户名通配符，如 user@*
	if strings.HasSuffix(pattern, "@*") {
		username := strings.TrimSuffix(pattern, "@*")
		return strings.HasPrefix(email, username+"@")
	}
	
	// 精确匹配
	return email == pattern
}

// IncrementForwardCount 增加转发次数
func (s *Service) IncrementForwardCount(ruleID int) error {
	_, err := s.db.Exec(`
		UPDATE global_forward_rules 
		SET forward_count = forward_count + 1, last_forward_at = ?
		WHERE id = ?
	`, time.Now(), ruleID)
	
	if err != nil {
		return fmt.Errorf("更新全局转发次数失败: %w", err)
	}
	
	return nil
}
