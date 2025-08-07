package models

import (
	"time"
)

// User 普通用户模型
type User struct {
	ID                int        `json:"id" db:"id"`
	Username          string     `json:"username" db:"username"`
	Password          string     `json:"-" db:"password"` // 不在JSON中显示密码
	Email             string     `json:"email" db:"email"`
	IsActive          bool       `json:"is_active" db:"is_active"`
	Contribution      int        `json:"contribution" db:"contribution"`      // 贡献度
	InviteCode        string     `json:"invite_code" db:"invite_code"`        // 邀请码
	InvitedBy         *int       `json:"invited_by" db:"invited_by"`          // 被谁邀请
	ResetToken        *string    `json:"-" db:"reset_token"`                  // 密码重置令牌
	ResetTokenExpires *time.Time `json:"-" db:"reset_token_expires"`          // 重置令牌过期时间
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

// Admin 管理员用户模型
type Admin struct {
	ID           int       `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Password     string    `json:"-" db:"password"`
	Email        string    `json:"email" db:"email"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	Contribution int       `json:"contribution" db:"contribution"`
	InviteCode   string    `json:"invite_code" db:"invite_code"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// Mailbox 邮箱模型
type Mailbox struct {
	ID        int       `json:"id" db:"id"`
	UserID    *int      `json:"user_id" db:"user_id"`       // 普通用户ID
	AdminID   *int      `json:"admin_id" db:"admin_id"`     // 管理员ID
	Email     string    `json:"email" db:"email"`           // 完整邮箱地址
	Password  string    `json:"-" db:"password"`            // 邮箱密码
	DomainID  int       `json:"domain_id" db:"domain_id"`   // 域名ID
	IsActive  bool      `json:"is_active" db:"is_active"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Domain 域名模型
type Domain struct {
	ID                         int       `json:"id" db:"id"`
	Name                       string    `json:"name" db:"name"`                                           // 域名
	IsVerified                 bool      `json:"is_verified" db:"is_verified"`                           // 是否已验证
	IsActive                   bool      `json:"is_active" db:"is_active"`
	MXRecord                   string    `json:"mx_record" db:"mx_record"`                               // MX记录
	ARecord                    string    `json:"a_record" db:"a_record"`                                 // A记录
	TXTRecord                  string    `json:"txt_record" db:"txt_record"`                             // TXT记录
	SPFRecord                  string    `json:"spf_record" db:"spf_record"`                             // SPF记录
	DMARCRecord                string    `json:"dmarc_record" db:"dmarc_record"`                         // DMARC记录
	DKIMRecord                 string    `json:"dkim_record" db:"dkim_record"`                           // DKIM记录
	PTRRecord                  string    `json:"ptr_record" db:"ptr_record"`                             // PTR记录
	SenderVerificationStatus   string    `json:"sender_verification_status" db:"sender_verification_status"`     // 发件验证状态
	ReceiverVerificationStatus string    `json:"receiver_verification_status" db:"receiver_verification_status"` // 收件验证状态
	CreatedAt                  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt                  time.Time `json:"updated_at" db:"updated_at"`
}

// Email 邮件模型
type Email struct {
	ID          int                `json:"id" db:"id"`
	MailboxID   int                `json:"mailbox_id" db:"mailbox_id"` // 邮箱ID
	FromAddr    string             `json:"from_addr" db:"from_addr"`   // 发件人
	ToAddr      string             `json:"to_addr" db:"to_addr"`       // 收件人
	Subject     string             `json:"subject" db:"subject"`       // 主题
	Body        string             `json:"body" db:"body"`             // 邮件内容
	IsRead      bool               `json:"is_read" db:"is_read"`       // 是否已读
	Folder      string             `json:"folder" db:"folder"`         // 文件夹 (inbox, sent, trash)
	Attachments []EmailAttachment  `json:"attachments,omitempty"`      // 附件列表
	CreatedAt   time.Time          `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at" db:"updated_at"`
}

// EmailAttachment 邮件附件模型
type EmailAttachment struct {
	ID          int       `json:"id" db:"id"`
	EmailID     int       `json:"email_id" db:"email_id"`
	Filename    string    `json:"filename" db:"filename"`
	ContentType string    `json:"content_type" db:"content_type"`
	FileSize    int64     `json:"file_size" db:"file_size"`
	Content     []byte    `json:"-" db:"content"`                    // 不在JSON中返回内容
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// EmailForward 邮件转发模型
type EmailForward struct {
	ID          int       `json:"id" db:"id"`
	MailboxID   int       `json:"mailbox_id" db:"mailbox_id"`     // 源邮箱ID
	ForwardTo   string    `json:"forward_to" db:"forward_to"`     // 转发到的邮箱
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}
