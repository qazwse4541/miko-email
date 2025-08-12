package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

// VerificationRule 验证码提取规则
type VerificationRule struct {
	ID          int       `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`                 // 规则名称
	Description string    `json:"description" db:"description"`   // 规则描述
	Pattern     string    `json:"pattern" db:"pattern"`           // 正则表达式
	Type        string    `json:"type" db:"type"`                 // 规则类型：default/custom
	Priority    int       `json:"priority" db:"priority"`         // 优先级，数字越小优先级越高
	Enabled     bool      `json:"enabled" db:"enabled"`           // 是否启用
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// ExtractedCode 提取的验证码信息
type ExtractedCode struct {
	Code        string `json:"code"`         // 验证码
	Pattern     string `json:"pattern"`      // 匹配的规则
	RuleName    string `json:"rule_name"`    // 规则名称
	MatchedText string `json:"matched_text"` // 匹配的原文
	Position    int    `json:"position"`     // 在邮件中的位置
}

// EmailVerificationCodes 邮件验证码提取结果
type EmailVerificationCodes struct {
	EmailID int             `json:"email_id"`
	Codes   []ExtractedCode `json:"codes"`
}

// Value 实现 driver.Valuer 接口
func (e ExtractedCode) Value() (driver.Value, error) {
	return json.Marshal(e)
}

// Scan 实现 sql.Scanner 接口
func (e *ExtractedCode) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, e)
	case string:
		return json.Unmarshal([]byte(v), e)
	}
	return nil
}

// DefaultVerificationRules 默认验证码规则
var DefaultVerificationRules = []VerificationRule{
	{
		Name:        "Telegram验证码",
		Description: "Telegram官方验证码格式",
		Pattern:     `Your code is:\s*([0-9]{6})`,
		Type:        "default",
		Priority:    1,
		Enabled:     true,
	},
	{
		Name:        "中文验证码（基础）",
		Description: "中文验证码基础格式",
		Pattern:     `(?:验证码为|验证码是|验证码：|验证码: )([0-9A-Za-z]{4,8})`,
		Type:        "default",
		Priority:    2,
		Enabled:     true,
	},
	{
		Name:        "安全代码",
		Description: "安全代码格式",
		Pattern:     `安全代码\s*[：:]\s*([0-9A-Za-z]{4,8})`,
		Type:        "default",
		Priority:    3,
		Enabled:     true,
	},
	{
		Name:        "英文验证码",
		Description: "英文验证码格式",
		Pattern:     `(?i)(?:security code|verification code|code)[:：]\s*([0-9A-Za-z]{4,8})`,
		Type:        "default",
		Priority:    4,
		Enabled:     true,
	},
	{
		Name:        "纯数字验证码",
		Description: "纯数字验证码格式",
		Pattern:     `验证码[：:]\s*([0-9]{4,8})`,
		Type:        "default",
		Priority:    5,
		Enabled:     true,
	},
	{
		Name:        "通用数字验证码",
		Description: "通用6位数字验证码",
		Pattern:     `\b([0-9]{6})\b`,
		Type:        "default",
		Priority:    10,
		Enabled:     true,
	},
}
