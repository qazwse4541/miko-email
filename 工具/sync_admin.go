package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"miko-email/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		showUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "sync":
		syncAdminFromConfig()
	case "show":
		showCurrentAdmin()
	case "reset":
		resetAdminPassword()
	default:
		fmt.Printf("未知命令: %s\n", command)
		showUsage()
	}
}

func showUsage() {
	fmt.Println("Miko邮箱管理员同步工具")
	fmt.Println("")
	fmt.Println("用法:")
	fmt.Println("  go run tools/sync_admin.go <命令>")
	fmt.Println("")
	fmt.Println("命令:")
	fmt.Println("  sync   - 从config.yaml同步管理员信息到数据库")
	fmt.Println("  show   - 显示当前数据库中的管理员信息")
	fmt.Println("  reset  - 重置管理员密码为配置文件中的密码")
	fmt.Println("")
	fmt.Println("示例:")
	fmt.Println("  go run tools/sync_admin.go sync")
	fmt.Println("  go run tools/sync_admin.go show")
}

func syncAdminFromConfig() {
	fmt.Println("=== 同步管理员信息 ===")
	fmt.Println("")

	// 加载配置
	cfg := config.Load()
	if config.GlobalYAMLConfig == nil {
		fmt.Println("❌ 未找到config.yaml文件，无法同步管理员信息")
		return
	}

	// 获取配置中的管理员信息
	username, password, email, enabled := config.GlobalYAMLConfig.GetAdminCredentials()
	
	fmt.Printf("📋 配置文件中的管理员信息:\n")
	fmt.Printf("  用户名: %s\n", username)
	fmt.Printf("  邮箱: %s\n", email)
	fmt.Printf("  启用: %v\n", enabled)
	fmt.Println("")

	// 连接数据库
	db, err := sql.Open("sqlite", cfg.DatabasePath)
	if err != nil {
		log.Fatal("连接数据库失败:", err)
	}
	defer db.Close()

	// 检查管理员是否存在
	var existingID int
	var existingUsername, existingEmail string
	var existingActive bool
	
	err = db.QueryRow("SELECT id, username, email, is_active FROM admins WHERE username = ?", username).Scan(
		&existingID, &existingUsername, &existingEmail, &existingActive)
	
	if err != nil && err != sql.ErrNoRows {
		log.Fatal("查询管理员失败:", err)
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("密码加密失败:", err)
	}

	if err == sql.ErrNoRows {
		// 管理员不存在，创建新管理员
		fmt.Println("🆕 管理员不存在，正在创建...")
		
		inviteCode := fmt.Sprintf("ADMIN_%d", time.Now().Unix())
		
		_, err = db.Exec(`
			INSERT INTO admins (username, password, email, is_active, contribution, invite_code, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, username, string(hashedPassword), email, enabled, 0, inviteCode, time.Now(), time.Now())
		
		if err != nil {
			log.Fatal("创建管理员失败:", err)
		}
		
		fmt.Println("✅ 管理员创建成功！")
	} else {
		// 管理员存在，更新信息
		fmt.Println("🔄 管理员已存在，正在更新...")
		
		_, err = db.Exec(`
			UPDATE admins 
			SET password = ?, email = ?, is_active = ?, updated_at = ?
			WHERE username = ?
		`, string(hashedPassword), email, enabled, time.Now(), username)
		
		if err != nil {
			log.Fatal("更新管理员失败:", err)
		}
		
		fmt.Println("✅ 管理员信息更新成功！")
		
		// 显示变更内容
		if existingEmail != email {
			fmt.Printf("  📧 邮箱: %s → %s\n", existingEmail, email)
		}
		if existingActive != enabled {
			fmt.Printf("  🔘 状态: %v → %v\n", existingActive, enabled)
		}
		fmt.Printf("  🔑 密码已更新\n")
	}
	
	fmt.Println("")
	fmt.Println("🎉 管理员信息同步完成！")
	fmt.Println("💡 现在可以使用新的管理员信息登录管理后台")
}

func showCurrentAdmin() {
	fmt.Println("=== 当前数据库中的管理员信息 ===")
	fmt.Println("")

	// 加载配置获取数据库路径
	cfg := config.Load()
	
	// 连接数据库
	db, err := sql.Open("sqlite", cfg.DatabasePath)
	if err != nil {
		log.Fatal("连接数据库失败:", err)
	}
	defer db.Close()

	// 查询所有管理员
	rows, err := db.Query(`
		SELECT id, username, email, is_active, contribution, invite_code, created_at, updated_at
		FROM admins
		ORDER BY id
	`)
	if err != nil {
		log.Fatal("查询管理员失败:", err)
	}
	defer rows.Close()

	fmt.Printf("%-4s %-15s %-25s %-8s %-6s %-15s %s\n", 
		"ID", "用户名", "邮箱", "状态", "贡献", "邀请码", "创建时间")
	fmt.Printf("%-4s %-15s %-25s %-8s %-6s %-15s %s\n", 
		"----", "---------------", "-------------------------", "--------", "------", "---------------", "-------------------")

	adminCount := 0
	for rows.Next() {
		var id, contribution int
		var username, email, inviteCode, createdAt, updatedAt string
		var isActive bool

		err := rows.Scan(&id, &username, &email, &isActive, &contribution, &inviteCode, &createdAt, &updatedAt)
		if err != nil {
			log.Printf("扫描行失败: %v", err)
			continue
		}

		status := "禁用"
		if isActive {
			status = "启用"
		}

		fmt.Printf("%-4d %-15s %-25s %-8s %-6d %-15s %s\n", 
			id, username, email, status, contribution, inviteCode, createdAt[:19])
		
		adminCount++
	}

	if adminCount == 0 {
		fmt.Println("❌ 数据库中没有管理员账号")
		fmt.Println("💡 请运行 'go run tools/sync_admin.go sync' 来创建管理员")
	} else {
		fmt.Printf("\n📊 总共 %d 个管理员账号\n", adminCount)
	}
}

func resetAdminPassword() {
	fmt.Println("=== 重置管理员密码 ===")
	fmt.Println("")

	// 加载配置
	cfg := config.Load()
	if config.GlobalYAMLConfig == nil {
		fmt.Println("❌ 未找到config.yaml文件")
		return
	}

	// 获取配置中的管理员信息
	username, password, _, _ := config.GlobalYAMLConfig.GetAdminCredentials()
	
	fmt.Printf("🔑 将重置管理员 '%s' 的密码为配置文件中的密码\n", username)
	fmt.Println("")

	// 连接数据库
	db, err := sql.Open("sqlite", cfg.DatabasePath)
	if err != nil {
		log.Fatal("连接数据库失败:", err)
	}
	defer db.Close()

	// 检查管理员是否存在
	var adminID int
	err = db.QueryRow("SELECT id FROM admins WHERE username = ?", username).Scan(&adminID)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("❌ 管理员 '%s' 不存在\n", username)
			fmt.Println("💡 请先运行 'go run tools/sync_admin.go sync' 来创建管理员")
			return
		}
		log.Fatal("查询管理员失败:", err)
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("密码加密失败:", err)
	}

	// 更新密码
	_, err = db.Exec("UPDATE admins SET password = ?, updated_at = ? WHERE username = ?", 
		string(hashedPassword), time.Now(), username)
	if err != nil {
		log.Fatal("更新密码失败:", err)
	}

	fmt.Println("✅ 管理员密码重置成功！")
	fmt.Printf("🌐 登录地址: http://localhost:8080/admin/login\n")
	fmt.Printf("👤 用户名: %s\n", username)
	fmt.Printf("🔑 密码: %s\n", password)
}
