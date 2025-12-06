# -*- coding: utf-8 -*-
"""
登录对话框
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
                             QLineEdit, QPushButton, QLabel, QGroupBox, QCheckBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
import json
import os
import base64

class LoginDialog(QDialog):
    """登录对话框"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.credentials_file = "login_credentials.json"
        self.init_ui()
        self.load_credentials()
    
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("登录 - 思凡邮箱群发工具")
        self.setFixedSize(400, 300)
        self.setModal(True)
        
        layout = QVBoxLayout(self)
        
        # 标题
        title_label = QLabel("思凡邮箱群发工具")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title_label)
        
        # 登录表单
        form_group = QGroupBox("登录信息")
        form_layout = QFormLayout(form_group)
        
        # 服务器地址
        self.server_edit = QLineEdit()
        self.server_edit.setText("http://111.119.198.162:8080")
        self.server_edit.setPlaceholderText("请输入服务器地址")
        form_layout.addRow("服务器地址:", self.server_edit)
        
        # 用户名
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("请输入用户名")
        form_layout.addRow("用户名:", self.username_edit)
        
        # 密码
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("请输入密码")
        form_layout.addRow("密码:", self.password_edit)
        
        # 记住密码选项
        self.remember_check = QCheckBox("记住账号密码")
        self.remember_check.setChecked(True)
        form_layout.addRow("", self.remember_check)
        
        layout.addWidget(form_group)
        
        # 按钮
        button_layout = QHBoxLayout()
        
        self.login_btn = QPushButton("登录")
        self.login_btn.setProperty("class", "success")
        self.login_btn.setDefault(True)
        self.login_btn.clicked.connect(self.accept)
        
        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self.reject)
        
        button_layout.addStretch()
        button_layout.addWidget(self.login_btn)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
        
        # 回车键登录
        self.password_edit.returnPressed.connect(self.accept)
    
    def _encode_password(self, password):
        """简单编码密码（Base64）"""
        if not password:
            return ""
        return base64.b64encode(password.encode('utf-8')).decode('utf-8')
    
    def _decode_password(self, encoded_password):
        """解码密码"""
        if not encoded_password:
            return ""
        try:
            return base64.b64decode(encoded_password.encode('utf-8')).decode('utf-8')
        except Exception:
            return ""
    
    def load_credentials(self):
        """加载保存的登录凭据"""
        try:
            if os.path.exists(self.credentials_file):
                with open(self.credentials_file, 'r', encoding='utf-8') as f:
                    credentials = json.load(f)
                
                # 填充保存的信息
                self.server_edit.setText(credentials.get('server', 'http://111.119.198.162:8080'))
                self.username_edit.setText(credentials.get('username', ''))
                
                # 解码密码
                encoded_password = credentials.get('password', '')
                decoded_password = self._decode_password(encoded_password)
                self.password_edit.setText(decoded_password)
                
                self.remember_check.setChecked(credentials.get('remember', True))
                
                # 如果有保存的用户名，焦点设置到密码框
                if credentials.get('username'):
                    self.password_edit.setFocus()
                else:
                    self.username_edit.setFocus()
                    
        except Exception as e:
            print(f"加载登录凭据失败: {e}")
            # 设置默认焦点
            self.username_edit.setFocus()
    
    def save_credentials(self):
        """保存登录凭据"""
        if not self.remember_check.isChecked():
            # 如果不记住密码，删除保存的凭据文件
            try:
                if os.path.exists(self.credentials_file):
                    os.remove(self.credentials_file)
            except Exception as e:
                print(f"删除登录凭据文件失败: {e}")
            return
        
        try:
            # 编码密码
            encoded_password = self._encode_password(self.password_edit.text())
            
            credentials = {
                'server': self.server_edit.text().strip(),
                'username': self.username_edit.text().strip(),
                'password': encoded_password,
                'remember': self.remember_check.isChecked()
            }
            
            with open(self.credentials_file, 'w', encoding='utf-8') as f:
                json.dump(credentials, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            print(f"保存登录凭据失败: {e}")
    
    def accept(self):
        """确认登录时保存凭据"""
        self.save_credentials()
        super().accept()
    
    def get_credentials(self):
        """获取登录凭据"""
        return (
            self.server_edit.text().strip(),
            self.username_edit.text().strip(),
            self.password_edit.text()
        )