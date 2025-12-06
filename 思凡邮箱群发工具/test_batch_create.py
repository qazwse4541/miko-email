#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试批量创建邮箱功能
"""

import requests
import json

def test_batch_create():
    """测试批量创建邮箱"""
    base_url = "http://111.119.198.162:8080"
    
    print("=== 批量创建邮箱测试 ===")
    
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
    
    # 获取可用域名
    print("\n获取可用域名...")
    response = session.get(f"{base_url}/api/domains/available")
    
    if response.status_code != 200:
        print(f"获取域名失败: {response.text}")
        return
    
    domain_result = response.json()
    if not domain_result.get('success'):
        print(f"获取域名失败: {domain_result}")
        return
    
    domains = domain_result.get('data', [])
    print(f"找到 {len(domains)} 个域名")
    
    if not domains:
        print("没有可用域名")
        return
    
    # 选择第一个域名
    domain_id = domains[0].get('id')
    domain_name = domains[0].get('name')
    print(f"使用域名: {domain_name} (ID: {domain_id})")
    
    # 测试批量创建邮箱
    print("\n测试批量创建邮箱...")
    
    # 准备批量创建数据
    batch_data = {
        'prefixes': ['test1', 'test2', 'test3'],
        'domain_id': domain_id
    }
    
    print(f"批量创建数据: {batch_data}")
    
    # 发送批量创建请求
    response = session.post(f"{base_url}/api/mailboxes/batch", json=batch_data)
    
    print(f"批量创建响应状态码: {response.status_code}")
    print(f"批量创建响应内容: {response.text}")
    
    if response.status_code == 200:
        try:
            batch_result = response.json()
            print(f"批量创建结果: {json.dumps(batch_result, indent=2, ensure_ascii=False)}")
            
            if batch_result.get('success'):
                print("✅ 批量创建请求成功!")
                
                # 分析返回的数据结构
                data = batch_result.get('data')
                print(f"\n数据结构分析:")
                print(f"data类型: {type(data)}")
                print(f"data内容: {data}")
                
                if data:
                    for key, value in data.items():
                        print(f"  {key}: {value} (类型: {type(value)})")
                        
            else:
                print(f"❌ 批量创建失败: {batch_result.get('message', '未知错误')}")
        except json.JSONDecodeError:
            print(f"❌ 响应不是有效的JSON: {response.text}")
    else:
        print(f"❌ 批量创建请求失败: HTTP {response.status_code}")
        print(f"错误内容: {response.text}")

if __name__ == "__main__":
    test_batch_create()