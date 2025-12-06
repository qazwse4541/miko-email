#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试邮件发送功能
"""

import requests
import json

def test_send_email():
    """测试邮件发送"""
    base_url = "http://111.119.198.162:8080"
    
    print("=== 邮件发送测试 ===")
    
    # 创建会话
    session = requests.Session()
    
    # 登录
    login_data = {
        'username': 'kimi',
        'password': 'tgx123456'
    }
    
    print("正在登录...")
    response = session.post(f"{base_url}/api/login", json=login_data)
    
    if response.status_code != 200:
        print(f"登录失败: {response.text}")
        return
    
    result = response.json()
    if not result.get('success'):
        print(f"登录失败: {result}")
        return
    
    print("✅ 登录成功!")
    
    # 获取邮箱列表
    print("\n获取邮箱列表...")
    response = session.get(f"{base_url}/api/mailboxes")
    
    if response.status_code != 200:
        print(f"获取邮箱失败: {response.text}")
        return
    
    mailbox_result = response.json()
    if not mailbox_result.get('success'):
        print(f"获取邮箱失败: {mailbox_result}")
        return
    
    mailboxes = mailbox_result.get('data', [])
    print(f"找到 {len(mailboxes)} 个邮箱")
    
    if not mailboxes:
        print("没有可用邮箱")
        return
    
    # 选择第一个邮箱作为发件人
    from_email = mailboxes[0].get('email', '')
    print(f"使用发件人: {from_email}")
    
    # 测试发送邮件
    print("\n测试发送邮件...")
    
    # 准备邮件数据
    email_data = {
        'from': from_email,
        'to': '2014131458@qq.com',  # 测试收件人
        'subject': '测试邮件',
        'content': '这是一封测试邮件，用于验证发送功能。'
    }
    
    print(f"邮件数据: {email_data}")
    
    # 发送邮件 - 使用multipart/form-data格式
    files = {
        'from': (None, email_data['from']),
        'to': (None, email_data['to']),
        'subject': (None, email_data['subject']),
        'content': (None, email_data['content'])
    }
    
    response = session.post(f"{base_url}/api/emails/send", files=files)
    
    print(f"发送响应状态码: {response.status_code}")
    print(f"发送响应内容: {response.text}")
    
    if response.status_code == 200:
        try:
            send_result = response.json()
            print(f"发送结果: {json.dumps(send_result, indent=2, ensure_ascii=False)}")
            
            if send_result.get('success'):
                print("✅ 邮件发送成功!")
            else:
                print(f"❌ 邮件发送失败: {send_result.get('message', '未知错误')}")
        except json.JSONDecodeError:
            print(f"❌ 响应不是有效的JSON: {response.text}")
    else:
        print(f"❌ 发送请求失败: HTTP {response.status_code}")
        print(f"错误内容: {response.text}")

if __name__ == "__main__":
    test_send_email()