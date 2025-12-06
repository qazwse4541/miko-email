#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试测试脚本 - 用于测试API连接和数据结构
"""

from api.client import MikoEmailAPI
import json

def test_api():
    """测试API连接"""
    print("=== 思凡邮箱群发工具 - API调试测试 ===")
    
    # 创建API客户端
    api = MikoEmailAPI("http://111.119.198.162:8080")
    
    # 获取登录信息
    print("\n请输入登录信息:")
    username = input("用户名: ")
    password = input("密码: ")
    
    try:
        # 登录
        print("\n正在登录...")
        response = api.login(username, password)
        print(f"登录响应: {json.dumps(response, indent=2, ensure_ascii=False)}")
        
        if response.get('success'):
            print("✅ 登录成功!")
            
            # 测试获取邮箱列表
            print("\n正在获取邮箱列表...")
            mailboxes = api.get_mailboxes()
            print(f"邮箱数量: {len(mailboxes)}")
            print(f"邮箱数据结构: {json.dumps(mailboxes, indent=2, ensure_ascii=False)}")
            
            # 分析邮箱数据
            if mailboxes:
                print("\n=== 邮箱数据分析 ===")
                for i, mailbox in enumerate(mailboxes):
                    print(f"\n邮箱 {i+1}:")
                    for key, value in mailbox.items():
                        print(f"  {key}: {value}")
                    
                    # 尝试构建邮箱地址
                    address = (mailbox.get('full_address') or 
                              mailbox.get('address') or 
                              mailbox.get('email') or
                              f"{mailbox.get('prefix', '')}@{mailbox.get('domain', '')}")
                    print(f"  构建的地址: {address}")
                    
                    # 检查状态
                    is_active = mailbox.get('is_active', mailbox.get('active', True))
                    print(f"  状态: {'激活' if is_active else '禁用'}")
            
            # 测试获取域名列表
            print("\n正在获取域名列表...")
            try:
                domains = api.get_available_domains()
                print(f"域名数量: {len(domains)}")
                print(f"域名数据: {json.dumps(domains, indent=2, ensure_ascii=False)}")
            except Exception as e:
                print(f"获取域名失败: {e}")
            
        else:
            print("❌ 登录失败!")
            
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_api()