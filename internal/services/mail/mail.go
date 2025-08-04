package mail

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
)

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Secure   string // "ssl" or "tls"
	FromName string
}

type Service struct {
	config SMTPConfig
}

func NewService(config SMTPConfig) *Service {
	return &Service{
		config: config,
	}
}

// SendEmail 发送邮件
func (s *Service) SendEmail(to, subject, body string) error {
	// 构建邮件内容
	from := fmt.Sprintf("%s <%s>", s.config.FromName, s.config.Username)
	
	msg := []byte(fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/html; charset=UTF-8\r\n"+
			"\r\n"+
			"%s\r\n",
		from, to, subject, body,
	))

	// 服务器地址
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	// 根据安全类型选择连接方式
	if s.config.Secure == "ssl" {
		return s.sendWithSSL(addr, to, msg)
	} else {
		return s.sendWithTLS(addr, to, msg)
	}
}

// sendWithSSL 使用SSL连接发送邮件
func (s *Service) sendWithSSL(addr, to string, msg []byte) error {
	// 创建TLS连接
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.config.Host,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("连接SMTP服务器失败: %v", err)
	}
	defer conn.Close()

	// 创建SMTP客户端
	client, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		return fmt.Errorf("创建SMTP客户端失败: %v", err)
	}
	defer client.Quit()

	// 认证
	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP认证失败: %v", err)
	}

	// 设置发件人
	if err := client.Mail(s.config.Username); err != nil {
		return fmt.Errorf("设置发件人失败: %v", err)
	}

	// 设置收件人
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("设置收件人失败: %v", err)
	}

	// 发送邮件内容
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("获取邮件写入器失败: %v", err)
	}

	_, err = writer.Write(msg)
	if err != nil {
		return fmt.Errorf("写入邮件内容失败: %v", err)
	}

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("关闭邮件写入器失败: %v", err)
	}

	return nil
}

// sendWithTLS 使用STARTTLS发送邮件
func (s *Service) sendWithTLS(addr, to string, msg []byte) error {
	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)
	return smtp.SendMail(addr, auth, s.config.Username, []string{to}, msg)
}

// SendPasswordResetEmail 发送密码重置邮件
func (s *Service) SendPasswordResetEmail(to, username, resetURL string) error {
	subject := "密码重置 - Miko邮箱系统"
	
	body := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>密码重置</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #667eea;
        }
        .logo {
            font-size: 2.5em;
            color: #667eea;
            margin-bottom: 10px;
        }
        .title {
            color: #333;
            margin: 0;
            font-size: 1.8em;
        }
        .content {
            margin-bottom: 30px;
        }
        .greeting {
            font-size: 1.1em;
            margin-bottom: 20px;
            color: #555;
        }
        .message {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            margin: 20px 0;
        }
        .reset-button {
            display: inline-block;
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 15px 30px;
            text-decoration: none;
            border-radius: 8px;
            font-weight: bold;
            margin: 20px 0;
            text-align: center;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }
        .reset-button:hover {
            background: linear-gradient(45deg, #5a6fd8, #6a42a0);
        }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #666;
            font-size: 0.9em;
        }
        .link {
            word-break: break-all;
            color: #667eea;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">📧</div>
            <h1 class="title">Miko邮箱系统</h1>
        </div>
        
        <div class="content">
            <div class="greeting">
                亲爱的 <strong>%s</strong>，您好！
            </div>
            
            <div class="message">
                <p>我们收到了您的密码重置请求。如果这是您本人的操作，请点击下面的按钮重置您的密码：</p>
            </div>
            
            <div style="text-align: center;">
                <a href="%s" class="reset-button">重置密码</a>
            </div>
            
            <div class="message">
                <p>如果按钮无法点击，请复制以下链接到浏览器地址栏：</p>
                <p><a href="%s" class="link">%s</a></p>
            </div>
            
            <div class="warning">
                <strong>⚠️ 安全提醒：</strong>
                <ul>
                    <li>此链接将在 <strong>1小时</strong> 后失效</li>
                    <li>如果您没有请求重置密码，请忽略此邮件</li>
                    <li>请不要将此链接分享给他人</li>
                    <li>重置密码后，请妥善保管您的新密码</li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p>此邮件由系统自动发送，请勿回复。</p>
            <p>如有疑问，请联系系统管理员。</p>
            <p>&copy; 2024 Miko邮箱系统 - YouDDNS</p>
        </div>
    </div>
</body>
</html>
`, username, resetURL, resetURL, resetURL)

	return s.SendEmail(to, subject, body)
}