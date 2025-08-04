package forward

import (
	"database/sql"
	"fmt"
	"time"
)

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// ForwardRule 转发规则结构
type ForwardRule struct {
	ID                int       `json:"id"`
	MailboxID         int       `json:"mailbox_id"`
	SourceEmail       string    `json:"source_email"`
	TargetEmail       string    `json:"target_email"`
	Enabled           bool      `json:"enabled"`
	KeepOriginal      bool      `json:"keep_original"`
	ForwardAttachments bool     `json:"forward_attachments"`
	SubjectPrefix     string    `json:"subject_prefix"`
	Description       string    `json:"description"`
	ForwardCount      int       `json:"forward_count"`
	LastForwardAt     *time.Time `json:"last_forward_at"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// CreateForwardRuleRequest 创建转发规则请求
type CreateForwardRuleRequest struct {
	SourceEmail        string `json:"source_email" binding:"required"`
	TargetEmail        string `json:"target_email" binding:"required"`
	Enabled            bool   `json:"enabled"`
	KeepOriginal       bool   `json:"keep_original"`
	ForwardAttachments bool   `json:"forward_attachments"`
	SubjectPrefix      string `json:"subject_prefix"`
	Description        string `json:"description"`
}

// GetForwardRulesByUser 获取用户的转发规则
func (s *Service) GetForwardRulesByUser(userID int) ([]ForwardRule, error) {
	query := `
		SELECT ef.id, ef.mailbox_id, ef.source_email, ef.target_email, ef.enabled, 
		       ef.keep_original, ef.forward_attachments, ef.subject_prefix, ef.description,
		       ef.forward_count, ef.last_forward_at, ef.created_at, ef.updated_at
		FROM email_forwards ef
		JOIN mailboxes m ON ef.mailbox_id = m.id
		WHERE m.user_id = ?
		ORDER BY ef.created_at DESC
	`
	
	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, fmt.Errorf("查询转发规则失败: %w", err)
	}
	defer rows.Close()

	var rules []ForwardRule
	for rows.Next() {
		var rule ForwardRule
		var lastForwardAt sql.NullTime
		
		err := rows.Scan(
			&rule.ID, &rule.MailboxID, &rule.SourceEmail, &rule.TargetEmail,
			&rule.Enabled, &rule.KeepOriginal, &rule.ForwardAttachments,
			&rule.SubjectPrefix, &rule.Description, &rule.ForwardCount,
			&lastForwardAt, &rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("扫描转发规则失败: %w", err)
		}
		
		if lastForwardAt.Valid {
			rule.LastForwardAt = &lastForwardAt.Time
		}
		
		rules = append(rules, rule)
	}

	return rules, nil
}

// GetForwardRuleByID 根据ID获取转发规则
func (s *Service) GetForwardRuleByID(ruleID int, userID int) (*ForwardRule, error) {
	query := `
		SELECT ef.id, ef.mailbox_id, ef.source_email, ef.target_email, ef.enabled, 
		       ef.keep_original, ef.forward_attachments, ef.subject_prefix, ef.description,
		       ef.forward_count, ef.last_forward_at, ef.created_at, ef.updated_at
		FROM email_forwards ef
		JOIN mailboxes m ON ef.mailbox_id = m.id
		WHERE ef.id = ? AND m.user_id = ?
	`
	
	var rule ForwardRule
	var lastForwardAt sql.NullTime
	
	err := s.db.QueryRow(query, ruleID, userID).Scan(
		&rule.ID, &rule.MailboxID, &rule.SourceEmail, &rule.TargetEmail,
		&rule.Enabled, &rule.KeepOriginal, &rule.ForwardAttachments,
		&rule.SubjectPrefix, &rule.Description, &rule.ForwardCount,
		&lastForwardAt, &rule.CreatedAt, &rule.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("转发规则不存在")
		}
		return nil, fmt.Errorf("查询转发规则失败: %w", err)
	}
	
	if lastForwardAt.Valid {
		rule.LastForwardAt = &lastForwardAt.Time
	}
	
	return &rule, nil
}

// CreateForwardRule 创建转发规则
func (s *Service) CreateForwardRule(userID int, req CreateForwardRuleRequest) (*ForwardRule, error) {
	// 首先获取邮箱ID
	var mailboxID int
	err := s.db.QueryRow("SELECT id FROM mailboxes WHERE email = ? AND user_id = ?", 
		req.SourceEmail, userID).Scan(&mailboxID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("源邮箱不存在或不属于当前用户")
		}
		return nil, fmt.Errorf("查询邮箱失败: %w", err)
	}

	// 检查是否已存在相同的转发规则
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM email_forwards WHERE mailbox_id = ? AND target_email = ?", 
		mailboxID, req.TargetEmail).Scan(&count)
	if err != nil {
		return nil, fmt.Errorf("检查转发规则失败: %w", err)
	}
	if count > 0 {
		return nil, fmt.Errorf("转发规则已存在")
	}

	// 创建转发规则
	now := time.Now()
	result, err := s.db.Exec(`
		INSERT INTO email_forwards (mailbox_id, source_email, target_email, enabled, 
		                           keep_original, forward_attachments, subject_prefix, 
		                           description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, mailboxID, req.SourceEmail, req.TargetEmail, req.Enabled, 
	   req.KeepOriginal, req.ForwardAttachments, req.SubjectPrefix, 
	   req.Description, now, now)

	if err != nil {
		return nil, fmt.Errorf("创建转发规则失败: %w", err)
	}

	ruleID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("获取转发规则ID失败: %w", err)
	}

	// 返回创建的规则
	return s.GetForwardRuleByID(int(ruleID), userID)
}

// UpdateForwardRule 更新转发规则
func (s *Service) UpdateForwardRule(ruleID int, userID int, req CreateForwardRuleRequest) error {
	// 首先检查规则是否存在且属于当前用户
	_, err := s.GetForwardRuleByID(ruleID, userID)
	if err != nil {
		return err
	}

	// 获取新的邮箱ID
	var mailboxID int
	err = s.db.QueryRow("SELECT id FROM mailboxes WHERE email = ? AND user_id = ?", 
		req.SourceEmail, userID).Scan(&mailboxID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("源邮箱不存在或不属于当前用户")
		}
		return fmt.Errorf("查询邮箱失败: %w", err)
	}

	// 更新转发规则
	_, err = s.db.Exec(`
		UPDATE email_forwards 
		SET mailbox_id = ?, source_email = ?, target_email = ?, enabled = ?, 
		    keep_original = ?, forward_attachments = ?, subject_prefix = ?, 
		    description = ?, updated_at = ?
		WHERE id = ?
	`, mailboxID, req.SourceEmail, req.TargetEmail, req.Enabled, 
	   req.KeepOriginal, req.ForwardAttachments, req.SubjectPrefix, 
	   req.Description, time.Now(), ruleID)

	if err != nil {
		return fmt.Errorf("更新转发规则失败: %w", err)
	}

	return nil
}

// DeleteForwardRule 删除转发规则
func (s *Service) DeleteForwardRule(ruleID int, userID int) error {
	// 首先检查规则是否存在且属于当前用户
	_, err := s.GetForwardRuleByID(ruleID, userID)
	if err != nil {
		return err
	}

	// 删除转发规则
	_, err = s.db.Exec("DELETE FROM email_forwards WHERE id = ?", ruleID)
	if err != nil {
		return fmt.Errorf("删除转发规则失败: %w", err)
	}

	return nil
}

// ToggleForwardRule 切换转发规则状态
func (s *Service) ToggleForwardRule(ruleID int, userID int, enabled bool) error {
	// 首先检查规则是否存在且属于当前用户
	_, err := s.GetForwardRuleByID(ruleID, userID)
	if err != nil {
		return err
	}

	// 更新状态
	_, err = s.db.Exec("UPDATE email_forwards SET enabled = ?, updated_at = ? WHERE id = ?", 
		enabled, time.Now(), ruleID)
	if err != nil {
		return fmt.Errorf("更新转发规则状态失败: %w", err)
	}

	return nil
}

// GetForwardStatistics 获取转发统计信息
func (s *Service) GetForwardStatistics(userID int) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// 总转发规则数
	var totalRules int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM email_forwards ef
		JOIN mailboxes m ON ef.mailbox_id = m.id
		WHERE m.user_id = ?
	`, userID).Scan(&totalRules)
	if err != nil {
		return nil, fmt.Errorf("查询总规则数失败: %w", err)
	}
	stats["total_rules"] = totalRules

	// 启用的规则数
	var activeRules int
	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM email_forwards ef
		JOIN mailboxes m ON ef.mailbox_id = m.id
		WHERE m.user_id = ? AND ef.enabled = 1
	`, userID).Scan(&activeRules)
	if err != nil {
		return nil, fmt.Errorf("查询启用规则数失败: %w", err)
	}
	stats["active_rules"] = activeRules

	// 总转发次数
	var totalForwards int
	err = s.db.QueryRow(`
		SELECT COALESCE(SUM(ef.forward_count), 0) FROM email_forwards ef
		JOIN mailboxes m ON ef.mailbox_id = m.id
		WHERE m.user_id = ?
	`, userID).Scan(&totalForwards)
	if err != nil {
		return nil, fmt.Errorf("查询总转发次数失败: %w", err)
	}
	stats["total_forwards"] = totalForwards

	// 今日转发次数（基于last_forward_at字段统计）
	var todayForwards int
	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM email_forwards ef
		JOIN mailboxes m ON ef.mailbox_id = m.id
		WHERE m.user_id = ? AND ef.last_forward_at >= datetime('now', 'start of day')
	`, userID).Scan(&todayForwards)
	if err != nil {
		return nil, fmt.Errorf("查询今日转发次数失败: %w", err)
	}
	stats["today_forwards"] = todayForwards

	return stats, nil
}

// IncrementForwardCount 增加转发次数
func (s *Service) IncrementForwardCount(ruleID int) error {
	_, err := s.db.Exec(`
		UPDATE email_forwards 
		SET forward_count = forward_count + 1, last_forward_at = ?
		WHERE id = ?
	`, time.Now(), ruleID)
	
	if err != nil {
		return fmt.Errorf("更新转发次数失败: %w", err)
	}
	
	return nil
}

// GetActiveForwardRules 获取指定邮箱的活跃转发规则
func (s *Service) GetActiveForwardRules(sourceEmail string) ([]ForwardRule, error) {
	query := `
		SELECT ef.id, ef.mailbox_id, ef.source_email, ef.target_email, ef.enabled, 
		       ef.keep_original, ef.forward_attachments, ef.subject_prefix, ef.description,
		       ef.forward_count, ef.last_forward_at, ef.created_at, ef.updated_at
		FROM email_forwards ef
		WHERE ef.source_email = ? AND ef.enabled = 1
	`
	
	rows, err := s.db.Query(query, sourceEmail)
	if err != nil {
		return nil, fmt.Errorf("查询活跃转发规则失败: %w", err)
	}
	defer rows.Close()

	var rules []ForwardRule
	for rows.Next() {
		var rule ForwardRule
		var lastForwardAt sql.NullTime
		
		err := rows.Scan(
			&rule.ID, &rule.MailboxID, &rule.SourceEmail, &rule.TargetEmail,
			&rule.Enabled, &rule.KeepOriginal, &rule.ForwardAttachments,
			&rule.SubjectPrefix, &rule.Description, &rule.ForwardCount,
			&lastForwardAt, &rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("扫描转发规则失败: %w", err)
		}
		
		if lastForwardAt.Valid {
			rule.LastForwardAt = &lastForwardAt.Time
		}
		
		rules = append(rules, rule)
	}

	return rules, nil
}
