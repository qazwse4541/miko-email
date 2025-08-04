package mailbox

import (
	"database/sql"
	"fmt"
	"time"

	"miko-email/internal/models"
	"github.com/google/uuid"
)

type Service struct {
	db *sql.DB
}

// MailboxResponse 邮箱响应结构体
type MailboxResponse struct {
	ID        int       `json:"id"`
	UserID    *int      `json:"user_id,omitempty"`
	AdminID   *int      `json:"admin_id,omitempty"`
	Email     string    `json:"email"`
	DomainID  int       `json:"domain_id"`
	Status    string    `json:"status"`    // 转换后的状态字段
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// GetDB 获取数据库连接
func (s *Service) GetDB() *sql.DB {
	return s.db
}

// GetUserMailboxes 获取用户的邮箱列表
func (s *Service) GetUserMailboxes(userID int, isAdmin bool) ([]MailboxResponse, error) {
	var query string
	if isAdmin {
		query = `
			SELECT m.id, m.admin_id, m.email, m.domain_id, m.is_active, m.created_at, m.updated_at
			FROM mailboxes m
			WHERE m.admin_id = ? AND m.is_active = 1
			ORDER BY m.created_at DESC
		`
	} else {
		query = `
			SELECT m.id, m.user_id, m.email, m.domain_id, m.is_active, m.created_at, m.updated_at
			FROM mailboxes m
			WHERE m.user_id = ? AND m.is_active = 1
			ORDER BY m.created_at DESC
		`
	}

	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 初始化为空数组而不是nil，确保JSON序列化时返回[]而不是null
	mailboxes := make([]MailboxResponse, 0)
	for rows.Next() {
		var mailbox models.Mailbox
		var response MailboxResponse

		if isAdmin {
			err = rows.Scan(&mailbox.ID, &mailbox.AdminID, &mailbox.Email,
				&mailbox.DomainID, &mailbox.IsActive, &mailbox.CreatedAt, &mailbox.UpdatedAt)
			if err != nil {
				return nil, err
			}
			response.AdminID = mailbox.AdminID
		} else {
			err = rows.Scan(&mailbox.ID, &mailbox.UserID, &mailbox.Email,
				&mailbox.DomainID, &mailbox.IsActive, &mailbox.CreatedAt, &mailbox.UpdatedAt)
			if err != nil {
				return nil, err
			}
			response.UserID = mailbox.UserID
		}

		// 转换基本字段
		response.ID = mailbox.ID
		response.Email = mailbox.Email
		response.DomainID = mailbox.DomainID
		response.CreatedAt = mailbox.CreatedAt
		response.UpdatedAt = mailbox.UpdatedAt

		// 转换状态字段
		if mailbox.IsActive {
			response.Status = "active"
		} else {
			response.Status = "deleted"
		}

		mailboxes = append(mailboxes, response)
	}

	return mailboxes, nil
}

// GetUserMailboxesRaw 获取用户的邮箱列表（返回原始models.Mailbox类型）
func (s *Service) GetUserMailboxesRaw(userID int, isAdmin bool) ([]models.Mailbox, error) {
	var query string
	if isAdmin {
		query = `
			SELECT m.id, m.admin_id, m.email, m.domain_id, m.is_active, m.created_at, m.updated_at
			FROM mailboxes m
			WHERE m.admin_id = ? AND m.is_active = 1
			ORDER BY m.created_at DESC
		`
	} else {
		query = `
			SELECT m.id, m.user_id, m.email, m.domain_id, m.is_active, m.created_at, m.updated_at
			FROM mailboxes m
			WHERE m.user_id = ? AND m.is_active = 1
			ORDER BY m.created_at DESC
		`
	}

	rows, err := s.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 初始化为空数组而不是nil，确保JSON序列化时返回[]而不是null
	mailboxes := make([]models.Mailbox, 0)
	for rows.Next() {
		var mailbox models.Mailbox
		if isAdmin {
			err = rows.Scan(&mailbox.ID, &mailbox.AdminID, &mailbox.Email,
				&mailbox.DomainID, &mailbox.IsActive, &mailbox.CreatedAt, &mailbox.UpdatedAt)
		} else {
			err = rows.Scan(&mailbox.ID, &mailbox.UserID, &mailbox.Email,
				&mailbox.DomainID, &mailbox.IsActive, &mailbox.CreatedAt, &mailbox.UpdatedAt)
		}
		if err != nil {
			return nil, err
		}
		mailboxes = append(mailboxes, mailbox)
	}

	return mailboxes, nil
}

// CreateMailbox 创建邮箱
func (s *Service) CreateMailbox(userID int, prefix string, domainID int, isAdmin bool) (*models.Mailbox, error) {
	// 获取域名
	var domainName string
	err := s.db.QueryRow("SELECT name FROM domains WHERE id = ? AND is_active = 1", domainID).Scan(&domainName)
	if err != nil {
		return nil, fmt.Errorf("域名不存在或已禁用")
	}

	fullEmail := fmt.Sprintf("%s@%s", prefix, domainName)

	// 检查邮箱是否已存在
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM mailboxes WHERE email = ?", fullEmail).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, fmt.Errorf("邮箱已存在")
	}

	// 生成邮箱密码
	password := uuid.New().String()[:8]

	// 插入邮箱
	var result sql.Result
	if isAdmin {
		result, err = s.db.Exec(`
			INSERT INTO mailboxes (admin_id, email, password, domain_id, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, userID, fullEmail, password, domainID, time.Now(), time.Now())
	} else {
		result, err = s.db.Exec(`
			INSERT INTO mailboxes (user_id, email, password, domain_id, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, userID, fullEmail, password, domainID, time.Now(), time.Now())
	}

	if err != nil {
		return nil, err
	}

	mailboxID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	mailbox := &models.Mailbox{
		ID:        int(mailboxID),
		Email:     fullEmail,
		DomainID:  domainID,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if isAdmin {
		mailbox.AdminID = &userID
	} else {
		mailbox.UserID = &userID
	}

	return mailbox, nil
}

// CreateMailboxWithPassword 创建邮箱（使用自定义密码）
func (s *Service) CreateMailboxWithPassword(userID int, prefix string, password string, domainID int, isAdmin bool) (*models.Mailbox, error) {
	// 获取域名
	var domainName string
	err := s.db.QueryRow("SELECT name FROM domains WHERE id = ? AND is_active = 1", domainID).Scan(&domainName)
	if err != nil {
		return nil, fmt.Errorf("域名不存在或已禁用")
	}

	fullEmail := fmt.Sprintf("%s@%s", prefix, domainName)

	// 检查邮箱是否已存在
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM mailboxes WHERE email = ?", fullEmail).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, fmt.Errorf("邮箱已存在")
	}

	// 插入邮箱
	var result sql.Result
	if isAdmin {
		result, err = s.db.Exec(`
			INSERT INTO mailboxes (admin_id, email, password, domain_id, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, userID, fullEmail, password, domainID, time.Now(), time.Now())
	} else {
		result, err = s.db.Exec(`
			INSERT INTO mailboxes (user_id, email, password, domain_id, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, userID, fullEmail, password, domainID, time.Now(), time.Now())
	}

	if err != nil {
		return nil, err
	}

	mailboxID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	// 返回创建的邮箱信息
	mailbox := &models.Mailbox{
		ID:        int(mailboxID),
		Email:     fullEmail,
		DomainID:  domainID,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if isAdmin {
		mailbox.AdminID = &userID
	} else {
		mailbox.UserID = &userID
	}

	return mailbox, nil
}

// BatchCreateMailboxes 批量创建邮箱
func (s *Service) BatchCreateMailboxes(userID int, prefixes []string, domainID int, isAdmin bool) ([]models.Mailbox, error) {
	// 获取域名
	var domainName string
	err := s.db.QueryRow("SELECT name FROM domains WHERE id = ? AND is_active = 1", domainID).Scan(&domainName)
	if err != nil {
		return nil, fmt.Errorf("域名不存在或已禁用")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var mailboxes []models.Mailbox
	for _, prefix := range prefixes {
		fullEmail := fmt.Sprintf("%s@%s", prefix, domainName)

		// 检查邮箱是否已存在
		var count int
		err = tx.QueryRow("SELECT COUNT(*) FROM mailboxes WHERE email = ?", fullEmail).Scan(&count)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			continue // 跳过已存在的邮箱
		}

		// 生成邮箱密码
		password := uuid.New().String()[:8]

		// 插入邮箱
		var result sql.Result
		if isAdmin {
			result, err = tx.Exec(`
				INSERT INTO mailboxes (admin_id, email, password, domain_id, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?)
			`, userID, fullEmail, password, domainID, time.Now(), time.Now())
		} else {
			result, err = tx.Exec(`
				INSERT INTO mailboxes (user_id, email, password, domain_id, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?)
			`, userID, fullEmail, password, domainID, time.Now(), time.Now())
		}

		if err != nil {
			return nil, err
		}

		mailboxID, err := result.LastInsertId()
		if err != nil {
			return nil, err
		}

		mailbox := models.Mailbox{
			ID:        int(mailboxID),
			Email:     fullEmail,
			DomainID:  domainID,
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if isAdmin {
			mailbox.AdminID = &userID
		} else {
			mailbox.UserID = &userID
		}

		mailboxes = append(mailboxes, mailbox)
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	return mailboxes, nil
}

// GetMailboxByEmail 根据邮箱地址获取邮箱信息
func (s *Service) GetMailboxByEmail(email string) (*models.Mailbox, error) {
	var mailbox models.Mailbox
	query := `
		SELECT id, user_id, admin_id, email, password, domain_id, is_active, created_at, updated_at
		FROM mailboxes
		WHERE email = ? AND is_active = 1
	`

	err := s.db.QueryRow(query, email).Scan(
		&mailbox.ID, &mailbox.UserID, &mailbox.AdminID, &mailbox.Email,
		&mailbox.Password, &mailbox.DomainID, &mailbox.IsActive,
		&mailbox.CreatedAt, &mailbox.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("邮箱不存在")
		}
		return nil, err
	}

	return &mailbox, nil
}

// GetMailboxByID 根据ID获取邮箱信息
func (s *Service) GetMailboxByID(mailboxID int) (*models.Mailbox, error) {
	var mailbox models.Mailbox
	query := `
		SELECT id, user_id, admin_id, email, password, domain_id, is_active, created_at, updated_at
		FROM mailboxes
		WHERE id = ? AND is_active = 1
	`

	err := s.db.QueryRow(query, mailboxID).Scan(
		&mailbox.ID, &mailbox.UserID, &mailbox.AdminID, &mailbox.Email,
		&mailbox.Password, &mailbox.DomainID, &mailbox.IsActive,
		&mailbox.CreatedAt, &mailbox.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &mailbox, nil
}

// GetMailboxPassword 获取邮箱密码
func (s *Service) GetMailboxPassword(mailboxID, userID int, isAdmin bool) (string, error) {
	// 验证邮箱所有权
	var ownerID int
	var password string
	var query string

	if isAdmin {
		query = `
			SELECT COALESCE(admin_id, 0), password
			FROM mailboxes
			WHERE id = ? AND is_active = 1
		`
	} else {
		query = `
			SELECT COALESCE(user_id, 0), password
			FROM mailboxes
			WHERE id = ? AND is_active = 1
		`
	}

	err := s.db.QueryRow(query, mailboxID).Scan(&ownerID, &password)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("邮箱不存在")
		}
		return "", err
	}

	// 检查权限
	if !isAdmin && ownerID != userID {
		return "", fmt.Errorf("无权限访问此邮箱")
	}

	return password, nil
}

// DeleteMailbox 删除邮箱
func (s *Service) DeleteMailbox(mailboxID, userID int, isAdmin bool) error {
	// 验证邮箱所有权
	var ownerID int
	var query string

	if isAdmin {
		query = "SELECT admin_id FROM mailboxes WHERE id = ? AND admin_id IS NOT NULL"
	} else {
		query = "SELECT user_id FROM mailboxes WHERE id = ? AND user_id IS NOT NULL"
	}

	err := s.db.QueryRow(query, mailboxID).Scan(&ownerID)
	if err != nil {
		return fmt.Errorf("邮箱不存在")
	}

	if ownerID != userID {
		return fmt.Errorf("无权限删除此邮箱")
	}

	// 硬删除邮箱及相关数据
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 删除相关邮件
	_, err = tx.Exec("DELETE FROM emails WHERE mailbox_id = ?", mailboxID)
	if err != nil {
		return err
	}

	// 删除转发规则
	_, err = tx.Exec("DELETE FROM email_forwards WHERE mailbox_id = ?", mailboxID)
	if err != nil {
		return err
	}

	// 删除邮箱
	_, err = tx.Exec("DELETE FROM mailboxes WHERE id = ?", mailboxID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// 管理员邮箱管理方法

// AdminMailboxResponse 管理员邮箱响应结构体
type AdminMailboxResponse struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	UserID    *int      `json:"user_id,omitempty"`
	AdminID   *int      `json:"admin_id,omitempty"`
	DomainID  int       `json:"domain_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MailboxStats 邮箱统计信息
type MailboxStats struct {
	InboxCount   int        `json:"inbox_count"`
	SentCount    int        `json:"sent_count"`
	LastActivity *time.Time `json:"last_activity,omitempty"`
}

// GetAllMailboxes 获取所有邮箱列表（管理员）
func (s *Service) GetAllMailboxes() ([]AdminMailboxResponse, error) {
	query := `
		SELECT m.id, m.email, m.user_id, m.admin_id, m.domain_id, m.is_active, m.created_at, m.updated_at,
		       COALESCE(u.username, a.username, '未知用户') as username
		FROM mailboxes m
		LEFT JOIN users u ON m.user_id = u.id
		LEFT JOIN admins a ON m.admin_id = a.id
		ORDER BY m.created_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// 初始化为空数组而不是nil，确保JSON序列化时返回[]而不是null
	mailboxes := make([]AdminMailboxResponse, 0)
	for rows.Next() {
		var mailbox AdminMailboxResponse
		var isActive bool

		err := rows.Scan(
			&mailbox.ID, &mailbox.Email, &mailbox.UserID, &mailbox.AdminID,
			&mailbox.DomainID, &isActive, &mailbox.CreatedAt, &mailbox.UpdatedAt,
			&mailbox.Username,
		)
		if err != nil {
			continue
		}

		// 转换状态
		if isActive {
			mailbox.Status = "active"
		} else {
			mailbox.Status = "suspended"
		}

		mailboxes = append(mailboxes, mailbox)
	}

	return mailboxes, nil
}

// UpdateMailboxStatus 更新邮箱状态（管理员）
func (s *Service) UpdateMailboxStatus(mailboxID int, status string) error {
	isActive := status == "active"

	_, err := s.db.Exec(
		"UPDATE mailboxes SET is_active = ?, updated_at = ? WHERE id = ?",
		isActive, time.Now(), mailboxID,
	)

	return err
}

// DeleteMailboxAdmin 删除邮箱（管理员）
func (s *Service) DeleteMailboxAdmin(mailboxID int) error {
	// 硬删除邮箱及相关数据
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 删除相关邮件
	_, err = tx.Exec("DELETE FROM emails WHERE mailbox_id = ?", mailboxID)
	if err != nil {
		return err
	}

	// 删除邮箱
	_, err = tx.Exec("DELETE FROM mailboxes WHERE id = ?", mailboxID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetMailboxStats 获取邮箱统计信息（管理员）
func (s *Service) GetMailboxStats(mailboxID int) (*MailboxStats, error) {
	stats := &MailboxStats{}

	// 获取收件数量
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM emails WHERE mailbox_id = ? AND folder = 'inbox'",
		mailboxID,
	).Scan(&stats.InboxCount)
	if err != nil {
		return nil, err
	}

	// 获取发件数量
	err = s.db.QueryRow(
		"SELECT COUNT(*) FROM emails WHERE mailbox_id = ? AND folder = 'sent'",
		mailboxID,
	).Scan(&stats.SentCount)
	if err != nil {
		return nil, err
	}

	// 获取最后活动时间
	var lastActivity sql.NullTime
	err = s.db.QueryRow(
		"SELECT MAX(created_at) FROM emails WHERE mailbox_id = ?",
		mailboxID,
	).Scan(&lastActivity)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if lastActivity.Valid {
		stats.LastActivity = &lastActivity.Time
	}

	return stats, nil
}

// UserStats 用户统计信息
type UserStats struct {
	TotalMailboxes int `json:"total_mailboxes"`
	UnreadEmails   int `json:"unread_emails"`
	SentEmails     int `json:"sent_emails"`
	TotalEmails    int `json:"total_emails"`
}

// GetUserStats 获取用户统计信息
func (s *Service) GetUserStats(userID int) (*UserStats, error) {
	stats := &UserStats{}

	// 获取用户的邮箱数量
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM mailboxes WHERE user_id = ? AND is_active = 1",
		userID,
	).Scan(&stats.TotalMailboxes)
	if err != nil {
		return nil, err
	}

	// 获取未读邮件数量（用户所有邮箱的未读邮件）
	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM emails e
		JOIN mailboxes m ON e.mailbox_id = m.id
		WHERE m.user_id = ? AND m.is_active = 1 AND e.folder = 'inbox' AND e.is_read = 0
	`, userID).Scan(&stats.UnreadEmails)
	if err != nil {
		return nil, err
	}

	// 获取已发送邮件数量
	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM emails e
		JOIN mailboxes m ON e.mailbox_id = m.id
		WHERE m.user_id = ? AND m.is_active = 1 AND e.folder = 'sent'
	`, userID).Scan(&stats.SentEmails)
	if err != nil {
		return nil, err
	}

	// 获取总邮件数量
	err = s.db.QueryRow(`
		SELECT COUNT(*) FROM emails e
		JOIN mailboxes m ON e.mailbox_id = m.id
		WHERE m.user_id = ? AND m.is_active = 1
	`, userID).Scan(&stats.TotalEmails)
	if err != nil {
		return nil, err
	}

	return stats, nil
}
