package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"miko-email/internal/models"
	"golang.org/x/crypto/bcrypt"
	"github.com/google/uuid"
)

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

// AuthenticateUser 验证普通用户
func (s *Service) AuthenticateUser(username, password string) (*models.User, error) {
	var user models.User
	var hashedPassword string

	query := `
		SELECT id, username, password, email, is_active, contribution, invite_code, invited_by, created_at, updated_at
		FROM users 
		WHERE username = ? AND is_active = 1
	`
	
	err := s.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &hashedPassword, &user.Email,
		&user.IsActive, &user.Contribution, &user.InviteCode,
		&user.InvitedBy, &user.CreatedAt, &user.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("用户不存在或已被禁用")
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return nil, fmt.Errorf("密码错误")
	}

	return &user, nil
}

// AuthenticateAdmin 验证管理员
func (s *Service) AuthenticateAdmin(username, password string) (*models.Admin, error) {
	var admin models.Admin
	var hashedPassword string

	query := `
		SELECT id, username, password, email, is_active, contribution, invite_code, created_at, updated_at
		FROM admins 
		WHERE username = ? AND is_active = 1
	`
	
	err := s.db.QueryRow(query, username).Scan(
		&admin.ID, &admin.Username, &hashedPassword, &admin.Email,
		&admin.IsActive, &admin.Contribution, &admin.InviteCode,
		&admin.CreatedAt, &admin.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("管理员不存在或已被禁用")
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return nil, fmt.Errorf("密码错误")
	}

	return &admin, nil
}

// RegisterUser 注册普通用户
func (s *Service) RegisterUser(username, password, email, domainPrefix string, domainID int, inviteCode string) (*models.User, error) {
	// 检查用户名是否已存在
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, fmt.Errorf("用户名已存在")
	}

	// 检查邮箱是否已存在
	err = s.db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", email).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, fmt.Errorf("邮箱已存在")
	}

	// 验证邀请码并获取邀请人ID
	var invitedBy *int
	if inviteCode != "" {
		var inviterID int
		// 先检查普通用户的邀请码
		err = s.db.QueryRow("SELECT id FROM users WHERE invite_code = ?", inviteCode).Scan(&inviterID)
		if err != nil {
			// 再检查管理员的邀请码
			err = s.db.QueryRow("SELECT id FROM admins WHERE invite_code = ?", inviteCode).Scan(&inviterID)
			if err != nil {
				return nil, fmt.Errorf("无效的邀请码")
			}
		}
		invitedBy = &inviterID
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// 生成用户邀请码
	userInviteCode := uuid.New().String()

	// 开始事务
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// 插入用户
	result, err := tx.Exec(`
		INSERT INTO users (username, password, email, invite_code, invited_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, username, string(hashedPassword), email, userInviteCode, invitedBy, time.Now(), time.Now())
	
	if err != nil {
		return nil, err
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	// 创建用户邮箱
	fullEmail := fmt.Sprintf("%s@%s", domainPrefix, getDomainName(s.db, domainID))
	mailboxPassword := uuid.New().String()[:8] // 生成8位随机密码
	
	_, err = tx.Exec(`
		INSERT INTO mailboxes (user_id, email, password, domain_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, userID, fullEmail, mailboxPassword, domainID, time.Now(), time.Now())
	
	if err != nil {
		return nil, err
	}

	// 如果有邀请人，增加邀请人的贡献度
	if invitedBy != nil {
		_, err = tx.Exec("UPDATE users SET contribution = contribution + 1 WHERE id = ?", *invitedBy)
		if err != nil {
			// 如果更新普通用户失败，尝试更新管理员
			_, err = tx.Exec("UPDATE admins SET contribution = contribution + 1 WHERE id = ?", *invitedBy)
			if err != nil {
				return nil, err
			}
		}
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}

	// 返回创建的用户信息
	user := &models.User{
		ID:           int(userID),
		Username:     username,
		Email:        email,
		IsActive:     true,
		Contribution: 0,
		InviteCode:   userInviteCode,
		InvitedBy:    invitedBy,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	return user, nil
}

// getDomainName 获取域名名称
func getDomainName(db *sql.DB, domainID int) string {
	var domainName string
	db.QueryRow("SELECT name FROM domains WHERE id = ?", domainID).Scan(&domainName)
	return domainName
}

// ChangePassword 修改密码
func (s *Service) ChangePassword(userID int, oldPassword, newPassword string, isAdmin bool) error {
	var hashedPassword string
	var query string
	
	if isAdmin {
		query = "SELECT password FROM admins WHERE id = ?"
	} else {
		query = "SELECT password FROM users WHERE id = ?"
	}
	
	err := s.db.QueryRow(query, userID).Scan(&hashedPassword)
	if err != nil {
		return fmt.Errorf("用户不存在")
	}

	// 验证旧密码
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(oldPassword)); err != nil {
		return fmt.Errorf("旧密码错误")
	}

	// 加密新密码
	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// 更新密码
	if isAdmin {
		query = "UPDATE admins SET password = ?, updated_at = ? WHERE id = ?"
	} else {
		query = "UPDATE users SET password = ?, updated_at = ? WHERE id = ?"
	}
	
	_, err = s.db.Exec(query, string(newHashedPassword), time.Now(), userID)
	return err
}

// GenerateResetToken 生成密码重置令牌
func (s *Service) GenerateResetToken(email string) (string, error) {
	// 检查用户是否存在
	var userID int
	var username string
	err := s.db.QueryRow("SELECT id, username FROM users WHERE email = ? AND is_active = 1", email).Scan(&userID, &username)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("该邮箱未注册或账户已被禁用")
		}
		return "", err
	}

	// 生成随机令牌
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("生成令牌失败")
	}
	token := hex.EncodeToString(tokenBytes)

	// 设置过期时间（1小时后）
	expiresAt := time.Now().Add(time.Hour)

	// 更新用户的重置令牌
	_, err = s.db.Exec(`
		UPDATE users 
		SET reset_token = ?, reset_token_expires = ?, updated_at = ? 
		WHERE id = ?
	`, token, expiresAt, time.Now(), userID)
	
	if err != nil {
		return "", fmt.Errorf("保存重置令牌失败")
	}

	return token, nil
}

// GetUserByEmail 根据邮箱获取用户信息
func (s *Service) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	query := `
		SELECT id, username, email, is_active, contribution, invite_code, invited_by, created_at, updated_at
		FROM users 
		WHERE email = ? AND is_active = 1
	`
	
	err := s.db.QueryRow(query, email).Scan(
		&user.ID, &user.Username, &user.Email,
		&user.IsActive, &user.Contribution, &user.InviteCode,
		&user.InvitedBy, &user.CreatedAt, &user.UpdatedAt,
	)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("用户不存在或已被禁用")
		}
		return nil, err
	}

	return &user, nil
}

// ResetPassword 使用令牌重置密码
func (s *Service) ResetPassword(token, newPassword string) error {
	// 验证令牌并获取用户信息
	var userID int
	var expiresAt time.Time
	
	query := `
		SELECT id, reset_token_expires 
		FROM users 
		WHERE reset_token = ? AND is_active = 1
	`
	
	err := s.db.QueryRow(query, token).Scan(&userID, &expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("无效的重置令牌")
		}
		return err
	}

	// 检查令牌是否过期
	if time.Now().After(expiresAt) {
		// 清除过期的令牌
		s.db.Exec("UPDATE users SET reset_token = NULL, reset_token_expires = NULL WHERE id = ?", userID)
		return fmt.Errorf("重置令牌已过期，请重新申请")
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("密码加密失败")
	}

	// 更新密码并清除重置令牌
	_, err = s.db.Exec(`
		UPDATE users 
		SET password = ?, reset_token = NULL, reset_token_expires = NULL, updated_at = ? 
		WHERE id = ?
	`, string(hashedPassword), time.Now(), userID)
	
	if err != nil {
		return fmt.Errorf("密码重置失败")
	}

	return nil
}
