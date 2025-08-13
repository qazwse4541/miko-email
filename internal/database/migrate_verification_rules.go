package database

import (
	"database/sql"
	"fmt"
	"log"
)

// MigrateVerificationRules 迁移验证码规则表，添加用户ID字段
func MigrateVerificationRules(db *sql.DB) error {
	log.Println("开始迁移验证码规则表...")

	// 检查是否已经有user_id字段
	var columnExists bool
	err := db.QueryRow(`
		SELECT COUNT(*) > 0 
		FROM pragma_table_info('verification_rules') 
		WHERE name = 'user_id'
	`).Scan(&columnExists)
	
	if err != nil {
		return fmt.Errorf("检查user_id字段失败: %v", err)
	}

	if columnExists {
		log.Println("user_id字段已存在，跳过迁移")
		return nil
	}

	// 开始事务
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("开始事务失败: %v", err)
	}
	defer tx.Rollback()

	// 创建新表结构
	_, err = tx.Exec(`
		CREATE TABLE verification_rules_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			name TEXT NOT NULL,
			description TEXT,
			pattern TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'custom',
			priority INTEGER DEFAULT 0,
			enabled BOOLEAN DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return fmt.Errorf("创建新表失败: %v", err)
	}

	// 复制数据（默认规则user_id为NULL，表示系统规则）
	_, err = tx.Exec(`
		INSERT INTO verification_rules_new (id, user_id, name, description, pattern, type, priority, enabled, created_at, updated_at)
		SELECT id, NULL, name, description, pattern, type, priority, enabled, created_at, updated_at
		FROM verification_rules
	`)
	if err != nil {
		return fmt.Errorf("复制数据失败: %v", err)
	}

	// 删除旧表
	_, err = tx.Exec("DROP TABLE verification_rules")
	if err != nil {
		return fmt.Errorf("删除旧表失败: %v", err)
	}

	// 重命名新表
	_, err = tx.Exec("ALTER TABLE verification_rules_new RENAME TO verification_rules")
	if err != nil {
		return fmt.Errorf("重命名表失败: %v", err)
	}

	// 创建索引
	_, err = tx.Exec("CREATE INDEX IF NOT EXISTS idx_verification_rules_user_id ON verification_rules(user_id)")
	if err != nil {
		return fmt.Errorf("创建user_id索引失败: %v", err)
	}

	_, err = tx.Exec("CREATE INDEX IF NOT EXISTS idx_verification_rules_enabled ON verification_rules(enabled)")
	if err != nil {
		return fmt.Errorf("创建enabled索引失败: %v", err)
	}

	_, err = tx.Exec("CREATE INDEX IF NOT EXISTS idx_verification_rules_priority ON verification_rules(priority)")
	if err != nil {
		return fmt.Errorf("创建priority索引失败: %v", err)
	}

	// 提交事务
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("提交事务失败: %v", err)
	}

	log.Println("验证码规则表迁移完成")
	return nil
}
