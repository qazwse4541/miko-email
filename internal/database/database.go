package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
	"miko-email/internal/config"
)

func Init(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// 设置SQLite编码为UTF-8
	if _, err := db.Exec("PRAGMA encoding = 'UTF-8'"); err != nil {
		return nil, fmt.Errorf("failed to set UTF-8 encoding: %w", err)
	}

	if err := createTables(db); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := createDefaultAdmin(db); err != nil {
		return nil, fmt.Errorf("failed to create default admin: %w", err)
	}

	if err := initDefaultVerificationRules(db); err != nil {
		return nil, fmt.Errorf("failed to init default verification rules: %w", err)
	}

	return db, nil
}

func createTables(db *sql.DB) error {
	queries := []string{
		// 普通用户表
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			is_active BOOLEAN DEFAULT 1,
			contribution INTEGER DEFAULT 0,
			invite_code TEXT UNIQUE NOT NULL,
			invited_by INTEGER,
			reset_token TEXT,
			reset_token_expires DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (invited_by) REFERENCES users(id)
		)`,

		// 管理员表
		`CREATE TABLE IF NOT EXISTS admins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			is_active BOOLEAN DEFAULT 1,
			contribution INTEGER DEFAULT 0,
			invite_code TEXT UNIQUE NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// 域名表
		`CREATE TABLE IF NOT EXISTS domains (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			is_verified BOOLEAN DEFAULT 0,
			is_active BOOLEAN DEFAULT 1,
			mx_record TEXT,
			a_record TEXT,
			txt_record TEXT,
			spf_record TEXT,
			dmarc_record TEXT,
			dkim_record TEXT,
			ptr_record TEXT,
			sender_verification_status TEXT DEFAULT 'pending',
			receiver_verification_status TEXT DEFAULT 'pending',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// 邮箱表
		`CREATE TABLE IF NOT EXISTS mailboxes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			admin_id INTEGER,
			email TEXT UNIQUE NOT NULL,
			password TEXT NOT NULL,
			domain_id INTEGER NOT NULL,
			is_active BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (admin_id) REFERENCES admins(id),
			FOREIGN KEY (domain_id) REFERENCES domains(id),
			CHECK ((user_id IS NOT NULL AND admin_id IS NULL) OR (user_id IS NULL AND admin_id IS NOT NULL))
		)`,

		// 邮件表
		`CREATE TABLE IF NOT EXISTS emails (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mailbox_id INTEGER NOT NULL,
			from_addr TEXT NOT NULL,
			to_addr TEXT NOT NULL,
			subject TEXT,
			body TEXT,
			is_read BOOLEAN DEFAULT 0,
			folder TEXT DEFAULT 'inbox',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id)
		)`,

		// 邮件附件表
		`CREATE TABLE IF NOT EXISTS email_attachments (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email_id INTEGER NOT NULL,
			filename TEXT NOT NULL,
			content_type TEXT NOT NULL,
			file_size INTEGER NOT NULL,
			content BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
		)`,

		// 邮件转发表
		`CREATE TABLE IF NOT EXISTS email_forwards (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mailbox_id INTEGER NOT NULL,
			source_email TEXT NOT NULL,
			target_email TEXT NOT NULL,
			enabled BOOLEAN DEFAULT 1,
			keep_original BOOLEAN DEFAULT 1,
			forward_attachments BOOLEAN DEFAULT 1,
			subject_prefix TEXT DEFAULT '[转发]',
			description TEXT,
			forward_count INTEGER DEFAULT 0,
			last_forward_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id)
		)`,

		// 全局转发规则表
		`CREATE TABLE IF NOT EXISTS global_forward_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			source_pattern TEXT NOT NULL,
			target_email TEXT NOT NULL,
			enabled BOOLEAN DEFAULT 1,
			keep_original BOOLEAN DEFAULT 1,
			forward_attachments BOOLEAN DEFAULT 1,
			subject_prefix TEXT DEFAULT '[全局转发]',
			description TEXT,
			priority INTEGER DEFAULT 0,
			forward_count INTEGER DEFAULT 0,
			last_forward_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,

		// 验证码规则表
		`CREATE TABLE IF NOT EXISTS verification_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			pattern TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'custom',
			priority INTEGER DEFAULT 0,
			enabled BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// 创建索引
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
		`CREATE INDEX IF NOT EXISTS idx_users_invite_code ON users(invite_code)`,
		`CREATE INDEX IF NOT EXISTS idx_admins_username ON admins(username)`,
		`CREATE INDEX IF NOT EXISTS idx_admins_email ON admins(email)`,
		`CREATE INDEX IF NOT EXISTS idx_email_attachments_email_id ON email_attachments(email_id)`,
		`CREATE INDEX IF NOT EXISTS idx_mailboxes_email ON mailboxes(email)`,
		`CREATE INDEX IF NOT EXISTS idx_mailboxes_user_id ON mailboxes(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_mailboxes_admin_id ON mailboxes(admin_id)`,
		`CREATE INDEX IF NOT EXISTS idx_emails_mailbox_id ON emails(mailbox_id)`,
		`CREATE INDEX IF NOT EXISTS idx_emails_folder ON emails(folder)`,
		`CREATE INDEX IF NOT EXISTS idx_emails_created_at ON emails(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_email_forwards_mailbox_id ON email_forwards(mailbox_id)`,
		`CREATE INDEX IF NOT EXISTS idx_email_forwards_source_email ON email_forwards(source_email)`,
		`CREATE INDEX IF NOT EXISTS idx_email_forwards_enabled ON email_forwards(enabled)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_rules_type ON verification_rules(type)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_rules_enabled ON verification_rules(enabled)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_rules_priority ON verification_rules(priority)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query: %s, error: %w", query, err)
		}
	}

	return nil
}

func createDefaultAdmin(db *sql.DB) error {
	// 获取配置中的管理员信息
	username, password, email, enabled := config.GetAdminCredentials()

	// 如果管理员被禁用，跳过创建
	if !enabled {
		return nil
	}

	// 检查是否已存在该用户名的管理员
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM admins WHERE username = ?", username).Scan(&count)
	if err != nil {
		return err
	}

	if count > 0 {
		// 管理员已存在，检查是否需要更新信息
		return updateExistingAdmin(db, username, password, email, enabled)
	}

	// 创建新管理员
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	inviteCode := generateInviteCode()

	_, err = db.Exec(`
		INSERT INTO admins (username, password, email, invite_code, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, username, string(hashedPassword), email, inviteCode, time.Now(), time.Now())

	return err
}

func updateExistingAdmin(db *sql.DB, username, password, email string, enabled bool) error {
	// 更新现有管理员的信息
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
		UPDATE admins
		SET password = ?, email = ?, is_active = ?, updated_at = ?
		WHERE username = ?
	`, string(hashedPassword), email, enabled, time.Now(), username)

	return err
}

func generateInviteCode() string {
	// 简单的邀请码生成，实际项目中应该使用更安全的方法
	return fmt.Sprintf("INVITE_%d", time.Now().Unix())
}

// runMigrations 运行数据库迁移
func runMigrations(db *sql.DB) error {
	// 检查是否需要添加密码重置字段
	if err := addPasswordResetFields(db); err != nil {
		return fmt.Errorf("failed to add password reset fields: %w", err)
	}

	return nil
}

// addPasswordResetFields 为用户表添加密码重置字段
func addPasswordResetFields(db *sql.DB) error {
	// 检查reset_token字段是否存在
	var columnExists int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('users') 
		WHERE name = 'reset_token'
	`).Scan(&columnExists)
	
	if err != nil {
		return err
	}

	// 如果字段不存在，则添加
	if columnExists == 0 {
		migrations := []string{
			`ALTER TABLE users ADD COLUMN reset_token TEXT`,
			`ALTER TABLE users ADD COLUMN reset_token_expires DATETIME`,
		}

		for _, migration := range migrations {
			if _, err := db.Exec(migration); err != nil {
				return fmt.Errorf("failed to execute migration: %s, error: %w", migration, err)
			}
		}
	}

	return nil
}

// initDefaultVerificationRules 初始化默认验证码规则
func initDefaultVerificationRules(db *sql.DB) error {
	// 检查是否已经初始化过
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM verification_rules WHERE type = 'default'").Scan(&count)
	if err != nil {
		return fmt.Errorf("检查默认验证码规则失败: %v", err)
	}

	if count > 0 {
		return nil // 已经初始化过
	}

	// 默认验证码规则
	defaultRules := []struct {
		Name        string
		Description string
		Pattern     string
		Priority    int
	}{
		{
			Name:        "Telegram验证码",
			Description: "Telegram官方验证码格式",
			Pattern:     `Your code is:\s*([0-9]{6})`,
			Priority:    1,
		},
		{
			Name:        "中文验证码（基础）",
			Description: "中文验证码基础格式",
			Pattern:     `(?:验证码为|验证码是|验证码：|验证码: )([0-9A-Za-z]{4,8})`,
			Priority:    2,
		},
		{
			Name:        "安全代码",
			Description: "安全代码格式",
			Pattern:     `安全代码\s*[：:]\s*([0-9A-Za-z]{4,8})`,
			Priority:    3,
		},
		{
			Name:        "英文验证码",
			Description: "英文验证码格式",
			Pattern:     `(?i)(?:security code|verification code|code)[:：]\s*([0-9A-Za-z]{4,8})`,
			Priority:    4,
		},
		{
			Name:        "纯数字验证码",
			Description: "纯数字验证码格式",
			Pattern:     `验证码[：:]\s*([0-9]{4,8})`,
			Priority:    5,
		},
		{
			Name:        "通用数字验证码",
			Description: "通用6位数字验证码",
			Pattern:     `\b([0-9]{6})\b`,
			Priority:    10,
		},
	}

	// 插入默认规则
	for _, rule := range defaultRules {
		_, err := db.Exec(`
			INSERT INTO verification_rules (name, description, pattern, type, priority, enabled, created_at, updated_at)
			VALUES (?, ?, ?, 'default', ?, 1, ?, ?)
		`, rule.Name, rule.Description, rule.Pattern, rule.Priority, time.Now(), time.Now())

		if err != nil {
			return fmt.Errorf("插入默认验证码规则失败: %v", err)
		}
	}

	return nil
}
