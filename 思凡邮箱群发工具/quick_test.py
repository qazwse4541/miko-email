#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速测试脚本
"""

import requests
import json

def quick_test():
    """快速测试API"""
    base_url = "http://111.119.198.162:8080"
    
    print("=== 快速API测试 ===")
    print(f"服务器地址: {base_url}")
    
    # 测试服务器连接
    try:
        response = requests.get(f"{base_url}/api/health", timeout=10)
        print(f"健康检查: {response.status_code}")
        if response.status_code == 200:
            print("✅ 服务器连接正常")
        else:
            print("⚠️ 服务器响应异常")
    except Exception as e:
        print(f"❌ 服务器连接失败: {e}")
        return
    
    # 获取登录信息
    username = input("\n请输入用户名: ")
    password = input("请输入密码: ")
    
    # 创建会话
    session = requests.Session()
    
    try:
        # 登录
        login_data = {
            'username': username,
            'password': password
        }
        
        print("\n正在登录...")
        response = session.post(f"{base_url}/api/login", json=login_data)
        print(f"登录状态码: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"登录结果: {json.dumps(result, indent=2, ensure_ascii=False)}")
            
            if result.get('success'):
                print("✅ 登录成功!")
                
                # 获取邮箱列表
                print("\n正在获取邮箱列表...")
                response = session.get(f"{base_url}/api/mailboxes")
                print(f"邮箱列表状态码: {response.status_code}")
                
                if response.status_code == 200:
                    mailbox_result = response.json()
                    print(f"邮箱列表结果: {json.dumps(mailbox_result, indent=2, ensure_ascii=False)}")
                    
                    if mailbox_result.get('success'):
                        mailboxes = mailbox_result.get('data', [])
                        print(f"\n找到 {len(mailboxes)} 个邮箱:")
                        
                        for i, mailbox in enumerate(mailboxes):
                            print(f"\n邮箱 {i+1}: {mailbox}")
                    else:
                        print("❌ 获取邮箱列表失败")
                else:
                    print(f"❌ 邮箱列表请求失败: {response.text}")
            else:
                print("❌ 登录失败")
        else:
            print(f"❌ 登录请求失败: {response.text}")
            
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    quick_test()