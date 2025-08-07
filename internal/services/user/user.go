package user

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"miko-email/internal/models"
)

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// UserWithStats 用户统计信息
type UserWithStats struct {
	models.User
	MailboxCount int    `json:"mailbox_count"`
	Status       string `json:"status"`
	InviterName  string `json:"inviter_name"`
}

// GetUsers 获取用户列表
func (s *Service) GetUsers() ([]UserWithStats, error) {
	query := `
		SELECT 
			u.id, u.username, u.email, u.is_active, u.contribution, 
			u.invite_code, u.invited_by, u.created_at, u.updated_at,
			COUNT(m.id) as mailbox_count,
			COALESCE(inviter.username, admin_inviter.username, '') as inviter_name
		FROM users u
		LEFT JOIN mailboxes m ON u.id = m.user_id AND m.is_active = 1
		LEFT JOIN users inviter ON u.invited_by = inviter.id
		LEFT JOIN admins admin_inviter ON u.invited_by = admin_inviter.id
		GROUP BY u.id, u.username, u.email, u.is_active, u.contribution, 
				 u.invite_code, u.invited_by, u.created_at, u.updated_at,
				 inviter.username, admin_inviter.username
		ORDER BY u.created_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserWithStats
	for rows.Next() {
		var user UserWithStats
		err = rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.IsActive, &user.Contribution,
			&user.InviteCode, &user.InvitedBy, &user.CreatedAt, &user.UpdatedAt,
			&user.MailboxCount, &user.InviterName,
		)
		if err != nil {
			return nil, err
		}

		// 设置状态
		if user.IsActive {
			user.Status = "active"
		} else {
			user.Status = "inactive"
		}

		users = append(users, user)
	}

	return users, nil
}

// GetUserByID 根据ID获取用户
func (s *Service) GetUserByID(userID int) (*UserWithStats, error) {
	query := `
		SELECT 
			u.id, u.username, u.email, u.is_active, u.contribution, 
			u.invite_code, u.invited_by, u.created_at, u.updated_at,
			COUNT(m.id) as mailbox_count,
			COALESCE(inviter.username, admin_inviter.username, '') as inviter_name
		FROM users u
		LEFT JOIN mailboxes m ON u.id = m.user_id AND m.is_active = 1
		LEFT JOIN users inviter ON u.invited_by = inviter.id
		LEFT JOIN admins admin_inviter ON u.invited_by = admin_inviter.id
		WHERE u.id = ?
		GROUP BY u.id, u.username, u.email, u.is_active, u.contribution, 
				 u.invite_code, u.invited_by, u.created_at, u.updated_at,
				 inviter.username, admin_inviter.username
	`

	var user UserWithStats
	err := s.db.QueryRow(query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.IsActive, &user.Contribution,
		&user.InviteCode, &user.InvitedBy, &user.CreatedAt, &user.UpdatedAt,
		&user.MailboxCount, &user.InviterName,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("用户不存在")
		}
		return nil, err
	}

	// 设置状态
	if user.IsActive {
		user.Status = "active"
	} else {
		user.Status = "inactive"
	}

	return &user, nil
}

// GetUserMailboxes 获取用户的邮箱列表
func (s *Service) GetUserMailboxes(userID int) ([]models.Mailbox, error) {
	query := `
		SELECT m.id, m.user_id, m.admin_id, m.email, m.domain_id, m.is_active, m.created_at, m.updated_at
		FROM mailboxes m
		WHERE m.user_id = ? AND m.is_active = 1
		ORDER BY m.created_at DESC
	`

	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mailboxes []models.Mailbox
	for rows.Next() {
		var mailbox models.Mailbox
		err = rows.Scan(
			&mailbox.ID, &mailbox.UserID, &mailbox.AdminID, &mailbox.Email,
			&mailbox.DomainID, &mailbox.IsActive, &mailbox.CreatedAt, &mailbox.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		mailboxes = append(mailboxes, mailbox)
	}

	return mailboxes, nil
}

// UpdateUserStatus 更新用户状态
func (s *Service) UpdateUserStatus(userID int, isActive bool) error {
	_, err := s.db.Exec("UPDATE users SET is_active = ?, updated_at = ? WHERE id = ?", 
		isActive, time.Now(), userID)
	return err
}

// DeleteUser 删除用户（硬删除）
func (s *Service) DeleteUser(userID int) error {
	// 检查用户是否存在
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("用户不存在")
	}

	// 开始事务
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. 删除用户的邮件附件（必须先删除，因为依赖邮件）
	_, err = tx.Exec(`DELETE FROM email_attachments
		WHERE email_id IN (
			SELECT e.id FROM emails e
			JOIN mailboxes m ON e.mailbox_id = m.id
			WHERE m.user_id = ?
		)`, userID)
	if err != nil {
		log.Printf("删除用户 %d 的邮件附件失败: %v", userID, err)
		return fmt.Errorf("删除邮件附件失败: %w", err)
	}

	// 2. 删除用户的邮件转发规则
	_, err = tx.Exec(`DELETE FROM email_forwards
		WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = ?)`, userID)
	if err != nil {
		log.Printf("删除用户 %d 的转发规则失败: %v", userID, err)
		return fmt.Errorf("删除转发规则失败: %w", err)
	}

	// 3. 删除用户的邮件
	_, err = tx.Exec(`DELETE FROM emails
		WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = ?)`, userID)
	if err != nil {
		log.Printf("删除用户 %d 的邮件失败: %v", userID, err)
		return fmt.Errorf("删除邮件失败: %w", err)
	}

	// 4. 删除用户的邮箱
	_, err = tx.Exec("DELETE FROM mailboxes WHERE user_id = ?", userID)
	if err != nil {
		log.Printf("删除用户 %d 的邮箱失败: %v", userID, err)
		return fmt.Errorf("删除邮箱失败: %w", err)
	}

	// 5. 删除用户记录
	_, err = tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		log.Printf("删除用户 %d 失败: %v", userID, err)
		return fmt.Errorf("删除用户记录失败: %w", err)
	}

	// 提交事务
	log.Printf("✅ 用户 %d 及其所有相关数据删除成功", userID)
	return tx.Commit()
}

// SuspendUser 暂停用户（软删除）
func (s *Service) SuspendUser(userID int) error {
	// 检查用户是否存在
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("用户不存在")
	}

	// 暂停用户（设置为非活跃状态）
	_, err = s.db.Exec("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?",
		time.Now(), userID)
	if err != nil {
		return err
	}

	// 同时禁用用户的所有邮箱
	_, err = s.db.Exec("UPDATE mailboxes SET is_active = 0, updated_at = ? WHERE user_id = ?",
		time.Now(), userID)

	return err
}
