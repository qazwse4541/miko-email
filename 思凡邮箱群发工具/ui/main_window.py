# -*- coding: utf-8 -*-
"""
主窗口
"""

from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QTabWidget, QMenuBar, QStatusBar, QMessageBox,
                             QLabel, QPushButton, QAction)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

from .login_dialog import LoginDialog
from .mailbox_tab import MailboxTab
from .compose_tab import ComposeTab
from .settings_tab import SettingsTab
from api.client import MikoEmailAPI

class MainWindow(QMainWindow):
    """主窗口类"""
    
    def __init__(self):
        super().__init__()
        self.api = None
        self.init_ui()
        self.show_login_dialog()
    
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("思凡邮箱群发工具 v1.0")
        self.setGeometry(100, 100, 1200, 800)
        
        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 创建布局
        layout = QVBoxLayout(central_widget)
        
        # 创建顶部信息栏
        self.create_info_bar(layout)
        
        # 创建选项卡
        self.create_tabs(layout)
        
        # 创建菜单栏
        self.create_menu_bar()
        
        # 创建状态栏
        self.create_status_bar()
    
    def create_info_bar(self, parent_layout):
        """创建信息栏"""
        info_layout = QHBoxLayout()
        
        # 用户信息
        self.user_label = QLabel("未登录")
        self.user_label.setFont(QFont("Arial", 10))
        info_layout.addWidget(QLabel("当前用户:"))
        info_layout.addWidget(self.user_label)
        
        info_layout.addStretch()
        
        # 登录/登出按钮
        self.login_btn = QPushButton("登录")
        self.login_btn.clicked.connect(self.show_login_dialog)
        info_layout.addWidget(self.login_btn)
        
        parent_layout.addLayout(info_layout)
    
    def create_tabs(self, parent_layout):
        """创建选项卡"""
        self.tab_widget = QTabWidget()
        
        # 邮箱账号管理
        self.mailbox_tab = MailboxTab()
        self.tab_widget.addTab(self.mailbox_tab, "邮箱账号")
        
        # 发送邮件
        self.compose_tab = ComposeTab()
        self.tab_widget.addTab(self.compose_tab, "发送邮件")
        
        # 发送设置
        self.settings_tab = SettingsTab()
        self.tab_widget.addTab(self.settings_tab, "发送设置")
        
        parent_layout.addWidget(self.tab_widget)
        
        # 初始状态禁用选项卡
        self.tab_widget.setEnabled(False)
    
    def create_menu_bar(self):
        """创建菜单栏"""
        menubar = self.menuBar()
        
        # 文件菜单
        file_menu = menubar.addMenu('文件')
        
        login_action = QAction('登录', self)
        login_action.triggered.connect(self.show_login_dialog)
        file_menu.addAction(login_action)
        
        logout_action = QAction('登出', self)
        logout_action.triggered.connect(self.logout)
        file_menu.addAction(logout_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('退出', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # 帮助菜单
        help_menu = menubar.addMenu('帮助')
        
        about_action = QAction('关于', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def create_status_bar(self):
        """创建状态栏"""
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")
    
    def show_login_dialog(self):
        """显示登录对话框"""
        dialog = LoginDialog(self)
        if dialog.exec_() == LoginDialog.Accepted:
            server_url, username, password = dialog.get_credentials()
            self.login(server_url, username, password)
    
    def login(self, server_url: str, username: str, password: str):
        """登录"""
        try:
            self.api = MikoEmailAPI(server_url)
            response = self.api.login(username, password)
            
            if response.get('success'):
                user = response.get('data', {}).get('user', {})
                self.user_label.setText(f"{user.get('username', 'Unknown')} ({user.get('email', '')})")
                self.login_btn.setText("登出")
                self.login_btn.clicked.disconnect()
                self.login_btn.clicked.connect(self.logout)
                
                # 启用选项卡
                self.tab_widget.setEnabled(True)
                
                # 设置API到各个选项卡
                self.mailbox_tab.set_api(self.api)
                self.compose_tab.set_api(self.api)
                self.settings_tab.set_api(self.api)
                
                # 强制刷新邮箱列表
                try:
                    self.compose_tab.load_mailboxes()
                except Exception as e:
                    print(f"加载发件人邮箱失败: {e}")
                
                self.status_bar.showMessage("登录成功")
                QMessageBox.information(self, "成功", "登录成功！")
            else:
                QMessageBox.warning(self, "错误", response.get('message', '登录失败'))
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"登录失败: {str(e)}")
    
    def logout(self):
        """登出"""
        if self.api:
            try:
                self.api.logout()
            except Exception:
                pass
        
        self.api = None
        self.user_label.setText("未登录")
        self.login_btn.setText("登录")
        self.login_btn.clicked.disconnect()
        self.login_btn.clicked.connect(self.show_login_dialog)
        
        # 禁用选项卡
        self.tab_widget.setEnabled(False)
        
        # 清理各个选项卡
        self.mailbox_tab.clear_data()
        self.compose_tab.clear_data()
        self.settings_tab.clear_data()
        
        self.status_bar.showMessage("已登出")
    
    def show_about(self):
        """显示关于对话框"""
        QMessageBox.about(self, "关于", 
                         "思凡邮箱群发工具 v1.0\n\n"
                         "基于miko邮箱域名API开发的邮件群发工具\n"
                         "支持批量邮箱管理和邮件群发功能")
    
    def closeEvent(self, event):
        """关闭事件"""
        if self.api:
            try:
                self.api.logout()
            except Exception:
                pass
        event.accept()