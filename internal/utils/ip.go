package utils

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// GetPublicIP 获取服务器的公网IP地址
func GetPublicIP() (string, error) {
	// 尝试多个IP查询服务
	services := []string{
		"https://api.ipify.org",
		"https://ipinfo.io/ip",
		"https://icanhazip.com",
		"https://ident.me",
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			ip := strings.TrimSpace(string(body))
			// 验证IP格式
			if net.ParseIP(ip) != nil {
				return ip, nil
			}
		}
	}

	return "", fmt.Errorf("无法获取公网IP地址")
}

// GetLocalIP 获取本地IP地址（备用方案）
func GetLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}

// GetServerIP 获取服务器IP地址，优先获取公网IP，失败则获取本地IP
func GetServerIP() string {
	if publicIP, err := GetPublicIP(); err == nil {
		return publicIP
	}

	if localIP, err := GetLocalIP(); err == nil {
		return localIP
	}

	// 最后的备用方案
	return "127.0.0.1"
}
