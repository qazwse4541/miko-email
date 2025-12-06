# -*- coding: utf-8 -*-
"""
API客户端
与miko邮箱系统API进行交互
"""

import requests
import json
from typing import Optional, Dict, List, Any

class MikoEmailAPI:
    """Miko邮箱API客户端"""
    
    def __init__(self, base_url: str = "http://111.119.198.162:8080"):
        self.base_url = base_url.rstrip('/')
        self.api_url = f"{self.base_url}/api"
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json; charset=utf-8'
        })
        self.is_logged_in = False
        self.current_user = None
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """发送HTTP请求"""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"请求失败: {str(e)}")
    
    def login(self, username: str, password: str) -> Dict[str, Any]:
        """用户登录"""
        data = {
            'username': username,
            'password': password
        }
        
        response = self._request('POST', '/login', json=data)
        
        if response.get('success'):
            self.is_logged_in = True
            self.current_user = response.get('data', {}).get('user')
            return response
        else:
            raise Exception(response.get('message', '登录失败'))
    
    def logout(self) -> Dict[str, Any]:
        """用户登出"""
        try:
            response = self._request('POST', '/logout')
            self.is_logged_in = False
            self.current_user = None
            return response
        except Exception:
            # 即使请求失败也清除本地状态
            self.is_logged_in = False
            self.current_user = None
            return {'success': True, 'message': '已登出'}
    
    def get_mailboxes(self) -> List[Dict[str, Any]]:
        """获取邮箱列表"""
        if not self.is_logged_in:
            raise Exception("请先登录")
        
        response = self._request('GET', '/mailboxes')
        if response.get('success'):
            return response.get('data', [])
        else:
            raise Exception(response.get('message', '获取邮箱列表失败'))
    
    def create_mailbox(self, prefix: str, domain_id: int, password: str) -> Dict[str, Any]:
        """创建邮箱"""
        if not self.is_logged_in:
            raise Exception("请先登录")
        
        data = {
            'prefix': prefix,
            'domain_id': domain_id,
            'password': password
        }
        
        response = self._request('POST', '/mailboxes', json=data)
        if response.get('success'):
            return response
        else:
            raise Exception(response.get('message', '创建邮箱失败'))
    
    def create_mailboxes_batch(self, prefixes: List[str], domain_id: int) -> Dict[str, Any]:
        """批量创建邮箱"""
        if not self.is_logged_in:
            raise Exception("请先登录")
        
        data = {
            'prefixes': prefixes,
            'domain_id': domain_id
        }
        
        response = self._request('POST', '/mailboxes/batch', json=data)
        if response.get('success'):
            return response
        else:
            raise Exception(response.get('message', '批量创建邮箱失败'))
    
    def get_mailbox_password(self, mailbox_id: int) -> str:
        """获取邮箱密码"""
        if not self.is_logged_in:
            raise Exception("请先登录")
        
        response = self._request('GET', f'/mailboxes/{mailbox_id}/password')
        if response.get('success'):
            return response.get('data', {}).get('password', '')
        else:
            raise Exception(response.get('message', '获取邮箱密码失败'))
    
    def delete_mailbox(self, mailbox_id: int) -> Dict[str, Any]:
        """删除邮箱"""
        if not self.is_logged_in:
            raise Exception("请先登录")
        
        response = self._request('DELETE', f'/mailboxes/{mailbox_id}')
        if response.get('success'):
            return response
        else:
            raise Exception(response.get('message', '删除邮箱失败'))
    
    def send_email(self, from_email: str, to_emails: List[str], subject: str, 
                   content: str, cc_emails: List[str] = None, 
                   bcc_emails: List[str] = None, is_html: bool = False) -> Dict[str, Any]:
        """发送邮件
        
        Args:
            from_email: 发件人邮箱
            to_emails: 收件人邮箱列表
            subject: 邮件主题
            content: 邮件内容
            cc_emails: 抄送邮箱列表
            bcc_emails: 密送邮箱列表
            is_html: 是否为HTML格式邮件
        """
        if not self.is_logged_in:
            raise Exception("请先登录")
        
        # 准备multipart/form-data数据
        files = {
            'from': (None, from_email),
            'to': (None, ','.join(to_emails)),
            'subject': (None, subject),
            'content': (None, content),
            'is_html': (None, '1' if is_html else '0')  # 添加HTML标志
        }
        
        if cc_emails:
            files['cc'] = (None, ','.join(cc_emails))
        if bcc_emails:
            files['bcc'] = (None, ','.join(bcc_emails))
        
        # 发送邮件使用multipart/form-data格式
        # 临时移除Content-Type头，让requests自动设置multipart/form-data
        original_headers = self.session.headers.copy()
        if 'Content-Type' in self.session.headers:
            del self.session.headers['Content-Type']
        
        try:
            response = self.session.post(
                f"{self.api_url}/emails/send",
                files=files
            )
            
            # 恢复原始headers
            self.session.headers.update(original_headers)
            
            result = response.json()
            if result.get('success'):
                return result
            else:
                raise Exception(result.get('message', '发送邮件失败'))
        except json.JSONDecodeError:
            # 恢复原始headers
            self.session.headers.update(original_headers)
            raise Exception(f"服务器响应错误: {response.text}")
        except Exception as e:
            # 恢复原始headers
            self.session.headers.update(original_headers)
            raise e
    
    def get_available_domains(self) -> List[Dict[str, Any]]:
        """获取可用域名列表"""
        response = self._request('GET', '/domains/available')
        if response.get('success'):
            return response.get('data', [])
        else:
            raise Exception(response.get('message', '获取域名列表失败'))
    
    def get_user_stats(self) -> Dict[str, Any]:
        """获取用户统计信息"""
        if not self.is_logged_in:
            raise Exception("请先登录")
        
        response = self._request('GET', '/mailboxes/stats')
        if response.get('success'):
            return response.get('data', {})
        else:
            raise Exception(response.get('message', '获取统计信息失败'))