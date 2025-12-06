# -*- coding: utf-8 -*-
"""
设置选项卡
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QLineEdit, QGroupBox, QSpinBox, QCheckBox,
                             QTextEdit, QComboBox, QMessageBox, QFormLayout)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
import json
import os

class SettingsTab(QWidget):
    """设置选项卡"""
    
    def __init__(self):
        super().__init__()
        self.api = None
        self.config_file = "config.json"
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        """初始化UI"""
        layout = QVBoxLayout(self)
        
        # 服务器设置
        server_group = QGroupBox("服务器设置")
        server_layout = QFormLayout(server_group)
        
        self.server_edit = QLineEdit()
        self.server_edit.setPlaceholderText("http://111.119.198.162:8080")
        server_layout.addRow("服务器地址:", self.server_edit)
        
        layout.addWidget(server_group)
        
        # 发送设置
        send_group = QGroupBox("默认发送设置")
        send_layout = QFormLayout(send_group)
        
        # 默认批次大小
        self.default_batch_spin = QSpinBox()
        self.default_batch_spin.setMinimum(1)
        self.default_batch_spin.setMaximum(100)
        self.default_batch_spin.setValue(1)
        send_layout.addRow("默认批次大小:", self.default_batch_spin)
        
        # 默认延时
        self.default_delay_spin = QSpinBox()
        self.default_delay_spin.setMinimum(0)
        self.default_delay_spin.setMaximum(60)
        self.default_delay_spin.setValue(0)
        send_layout.addRow("默认延时(秒):", self.default_delay_spin)
        
        # 自动保存草稿
        self.auto_save_check = QCheckBox("自动保存邮件草稿")
        self.auto_save_check.setChecked(True)
        send_layout.addRow("", self.auto_save_check)
        
        layout.addWidget(send_group)
        
        # 邮件模板
        template_group = QGroupBox("邮件模板")
        template_layout = QVBoxLayout(template_group)
        
        # 模板选择
        template_select_layout = QHBoxLayout()
        template_select_layout.addWidget(QLabel("选择模板:"))
        
        self.template_combo = QComboBox()
        self.template_combo.addItem("默认模板")
        self.template_combo.addItem("营销邮件模板")
        self.template_combo.addItem("通知邮件模板")
        self.template_combo.addItem("HTML基础模板")
        self.template_combo.addItem("HTML营销模板")
        template_select_layout.addWidget(self.template_combo)
        
        self.load_template_btn = QPushButton("加载模板")
        self.load_template_btn.clicked.connect(self.load_template)
        template_select_layout.addWidget(self.load_template_btn)
        
        template_select_layout.addStretch()
        template_layout.addLayout(template_select_layout)
        
        # 模板类型
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("模板类型:"))
        self.template_type_combo = QComboBox()
        self.template_type_combo.addItem("纯文本")
        self.template_type_combo.addItem("HTML")
        self.template_type_combo.currentIndexChanged.connect(self.on_template_type_changed)
        type_layout.addWidget(self.template_type_combo)
        type_layout.addStretch()
        template_layout.addLayout(type_layout)
        
        # 模板主题
        subject_layout = QHBoxLayout()
        subject_layout.addWidget(QLabel("模板主题:"))
        self.template_subject_edit = QLineEdit()
        subject_layout.addWidget(self.template_subject_edit)
        template_layout.addLayout(subject_layout)
        
        # 模板内容
        template_layout.addWidget(QLabel("模板内容:"))
        self.template_content_text = QTextEdit()
        self.template_content_text.setMaximumHeight(150)
        template_layout.addWidget(self.template_content_text)
        
        # 模板操作按钮
        template_btn_layout = QHBoxLayout()
        
        self.save_template_btn = QPushButton("保存模板")
        self.save_template_btn.setProperty("class", "success")
        self.save_template_btn.clicked.connect(self.save_template)
        template_btn_layout.addWidget(self.save_template_btn)
        
        self.apply_template_btn = QPushButton("应用到发送页面")
        self.apply_template_btn.clicked.connect(self.apply_template)
        template_btn_layout.addWidget(self.apply_template_btn)
        
        template_btn_layout.addStretch()
        template_layout.addLayout(template_btn_layout)
        
        layout.addWidget(template_group)
        
        # 系统信息
        info_group = QGroupBox("系统信息")
        info_layout = QVBoxLayout(info_group)
        
        self.user_info_label = QLabel("用户信息: 未登录")
        info_layout.addWidget(self.user_info_label)
        
        self.stats_label = QLabel("统计信息: 暂无数据")
        info_layout.addWidget(self.stats_label)
        
        # 刷新按钮
        refresh_btn = QPushButton("刷新信息")
        refresh_btn.clicked.connect(self.refresh_info)
        info_layout.addWidget(refresh_btn)
        
        layout.addWidget(info_group)
        
        # 保存设置按钮
        save_layout = QHBoxLayout()
        save_layout.addStretch()
        
        self.save_settings_btn = QPushButton("保存设置")
        self.save_settings_btn.setProperty("class", "success")
        self.save_settings_btn.clicked.connect(self.save_settings)
        save_layout.addWidget(self.save_settings_btn)
        
        layout.addLayout(save_layout)
        
        layout.addStretch()
    
    def set_api(self, api):
        """设置API客户端"""
        self.api = api
        self.refresh_info()
    
    def load_settings(self):
        """加载设置"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 服务器设置
                self.server_edit.setText(config.get('server_url', 'http://111.119.198.162:8080'))
                
                # 发送设置
                self.default_batch_spin.setValue(config.get('default_batch_size', 1))
                self.default_delay_spin.setValue(config.get('default_delay', 0))
                self.auto_save_check.setChecked(config.get('auto_save_draft', True))
                
                # 更新模板下拉框
                self.template_combo.clear()
                templates = config.get('templates', {})
                if templates:
                    # 添加所有模板到下拉框
                    for template_name in templates.keys():
                        self.template_combo.addItem(template_name)
                    
                    # 加载第一个模板
                    first_template_name = list(templates.keys())[0]
                    first_template = templates[first_template_name]
                    self.template_subject_edit.setText(first_template.get('subject', ''))
                    self.template_content_text.setPlainText(first_template.get('content', ''))
                    
                    # 设置模板类型
                    is_html = first_template.get('is_html', False)
                    self.template_type_combo.setCurrentIndex(1 if is_html else 0)
                    
        except Exception as e:
            print(f"加载设置失败: {e}")
    
    def save_settings(self):
        """保存设置"""
        try:
            # 读取当前配置以保留模板
            current_config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    current_config = json.load(f)
            
            # 更新配置
            config = {
                'server_url': self.server_edit.text().strip(),
                'default_batch_size': self.default_batch_spin.value(),
                'default_delay': self.default_delay_spin.value(),
                'auto_save_draft': self.auto_save_check.isChecked(),
                'templates': current_config.get('templates', self.get_templates())
            }
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            
            QMessageBox.information(self, "成功", "设置保存成功！")
            
        except Exception as e:
            QMessageBox.warning(self, "错误", f"保存设置失败: {str(e)}")
    
    def get_templates(self):
        """获取模板配置"""
        try:
            # 从配置文件读取模板
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    if 'templates' in config:
                        return config['templates']
        except Exception as e:
            print(f"读取模板配置失败: {e}")
        
        # 如果读取失败或没有模板，返回默认模板
        return {
            "默认模板": {
                "subject": "默认邮件主题",
                "content": "这是默认邮件内容模板。",
                "is_html": False
            },
            "营销邮件模板": {
                "subject": "【优惠活动】限时特价，不容错过！",
                "content": "亲爱的用户，\n\n我们为您准备了特别优惠活动...\n\n祝好！",
                "is_html": False
            },
            "通知邮件模板": {
                "subject": "【系统通知】重要信息提醒",
                "content": "尊敬的用户，\n\n这是一条重要的系统通知...\n\n谢谢！",
                "is_html": False
            },
            "HTML基础模板": {
                "subject": "HTML邮件测试",
                "content": """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HTML邮件</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f4f4f4; padding: 20px; text-align: center; }
        .content { padding: 20px; }
        .footer { background: #f4f4f4; padding: 10px; text-align: center; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>欢迎使用我们的服务</h1>
        </div>
        <div class="content">
            <p>尊敬的用户，</p>
            <p>这是一封HTML格式的邮件。您可以在这里添加丰富的内容，包括：</p>
            <ul>
                <li>格式化文本</li>
                <li>链接和图片</li>
                <li>表格和列表</li>
            </ul>
            <p>感谢您的关注！</p>
        </div>
        <div class="footer">
            <p>此邮件由系统自动发送，请勿回复。</p>
        </div>
    </div>
</body>
</html>""",
                "is_html": True
            },
            "HTML营销模板": {
                "subject": "🎉 特别优惠 - 限时抢购！",
                "content": """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>特别优惠</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f6f6f6; }
        .container { max-width: 600px; margin: 0 auto; background: white; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .content { padding: 30px; }
        .offer-box { background: #ff6b6b; color: white; padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0; }
        .btn { display: inline-block; background: #4ecdc4; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; }
        .footer { background: #333; color: white; padding: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎉 限时特惠活动</h1>
            <p>错过今天，再等一年！</p>
        </div>
        <div class="content">
            <h2>亲爱的客户，</h2>
            <p>我们为您准备了年度最大优惠！</p>
            
            <div class="offer-box">
                <h3>🔥 全场商品 5折起 🔥</h3>
                <p>活动时间：即日起至本月底</p>
            </div>
            
            <p>立即行动，享受超值优惠：</p>
            <ul>
                <li>✅ 全场商品5折起</li>
                <li>✅ 满额免运费</li>
                <li>✅ 7天无理由退换</li>
            </ul>
            
            <p style="text-align: center;">
                <a href="#" class="btn">立即抢购</a>
            </p>
        </div>
        <div class="footer">
            <p>感谢您的支持 | 客服热线：400-123-4567</p>
        </div>
    </div>
</body>
</html>""",
                "is_html": True
            },
            "HTML通知模板": {
                "subject": "【重要通知】系统更新提醒",
                "content": """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>系统通知</title>
    <style>
        body { font-family: 'Microsoft YaHei', Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }
        .container { max-width: 600px; margin: 20px auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; }
        .content { padding: 30px; }
        .notice-box { background: #e8f4fd; border-left: 4px solid #3498db; padding: 15px; margin: 20px 0; }
        .warning-box { background: #fef9e7; border-left: 4px solid #f39c12; padding: 15px; margin: 20px 0; }
        .footer { background: #ecf0f1; padding: 15px; text-align: center; color: #7f8c8d; }
        .timestamp { color: #95a5a6; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📢 系统通知</h1>
            <p class="timestamp">发送时间：2025年1月1日 10:00</p>
        </div>
        <div class="content">
            <h2>尊敬的用户，</h2>
            
            <div class="notice-box">
                <h3>🔧 系统维护通知</h3>
                <p>为了提供更好的服务体验，我们将在以下时间进行系统维护：</p>
                <ul>
                    <li><strong>维护时间：</strong>2025年1月2日 02:00 - 06:00</li>
                    <li><strong>影响范围：</strong>所有在线服务</li>
                    <li><strong>预计时长：</strong>4小时</li>
                </ul>
            </div>
            
            <div class="warning-box">
                <h3>⚠️ 注意事项</h3>
                <p>维护期间，您可能无法正常使用以下功能：</p>
                <ul>
                    <li>登录和注册</li>
                    <li>数据同步</li>
                    <li>在线客服</li>
                </ul>
            </div>
            
            <p>维护完成后，系统将自动恢复正常。给您带来的不便，我们深表歉意。</p>
            
            <p>如有紧急问题，请联系我们的客服团队。</p>
        </div>
        <div class="footer">
            <p>此邮件由系统自动发送，请勿直接回复</p>
            <p>如需帮助，请访问我们的帮助中心或联系客服</p>
        </div>
    </div>
</body>
</html>""",
                "is_html": True
            }
        }
    
    def on_template_type_changed(self, index):
        """模板类型改变时的处理"""
        is_html = (index == 1)  # 1表示HTML类型
        
        # 根据类型调整编辑器
        if is_html:
            # 可以在这里添加HTML语法高亮等功能
            pass
    
    def load_template(self):
        """加载模板"""
        template_name = self.template_combo.currentText()
        templates = self.get_templates()
        
        if template_name in templates:
            template = templates[template_name]
            self.template_subject_edit.setText(template['subject'])
            self.template_content_text.setPlainText(template['content'])
            
            # 设置模板类型
            is_html = template.get('is_html', False)
            self.template_type_combo.setCurrentIndex(1 if is_html else 0)
    
    def save_template(self):
        """保存模板"""
        template_name = self.template_combo.currentText()
        subject = self.template_subject_edit.text().strip()
        content = self.template_content_text.toPlainText().strip()
        is_html = self.template_type_combo.currentIndex() == 1
        
        if not subject or not content:
            QMessageBox.warning(self, "错误", "请输入模板主题和内容")
            return
        
        try:
            # 读取当前配置
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            
            # 确保templates字段存在
            if 'templates' not in config:
                config['templates'] = {}
            
            # 更新或添加模板
            config['templates'][template_name] = {
                "subject": subject,
                "content": content,
                "is_html": is_html
            }
            
            # 保存到配置文件
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            
            QMessageBox.information(self, "成功", f"模板 '{template_name}' 保存成功！")
            
        except Exception as e:
            QMessageBox.warning(self, "错误", f"保存模板失败: {str(e)}")
    
    def apply_template(self):
        """应用模板到发送页面"""
        subject = self.template_subject_edit.text().strip()
        content = self.template_content_text.toPlainText().strip()
        is_html = self.template_type_combo.currentIndex() == 1
        
        if not subject or not content:
            QMessageBox.warning(self, "错误", "请先选择或编辑模板")
            return
        
        # 获取主窗口的发送选项卡
        main_window = self.parent()
        while main_window and not hasattr(main_window, 'compose_tab'):
            main_window = main_window.parent()
        
        if main_window and hasattr(main_window, 'compose_tab'):
            main_window.compose_tab.subject_edit.setText(subject)
            main_window.compose_tab.content_text.setPlainText(content)
            
            # 设置HTML标志
            if hasattr(main_window.compose_tab, 'html_checkbox'):
                main_window.compose_tab.html_checkbox.setChecked(is_html)
            
            # 切换到发送选项卡
            main_window.tab_widget.setCurrentWidget(main_window.compose_tab)
            
            template_type = "HTML" if is_html else "纯文本"
            QMessageBox.information(self, "成功", f"{template_type}模板已应用到发送页面！")
        else:
            QMessageBox.warning(self, "错误", "无法找到发送页面")
    
    def refresh_info(self):
        """刷新系统信息"""
        if not self.api or not self.api.is_logged_in:
            self.user_info_label.setText("用户信息: 未登录")
            self.stats_label.setText("统计信息: 暂无数据")
            return
        
        try:
            # 用户信息
            user = self.api.current_user
            if user:
                user_text = f"用户: {user.get('username', 'Unknown')} | 邮箱: {user.get('email', 'Unknown')}"
                if user.get('is_admin', False):
                    user_text += " | 管理员"
                self.user_info_label.setText(f"用户信息: {user_text}")
            
            # 统计信息 - 直接从邮箱列表获取统计
            try:
                mailboxes = self.api.get_mailboxes()
                mailbox_count = len(mailboxes)
                
                # 计算激活邮箱数量
                active_count = sum(1 for mb in mailboxes if mb.get('status') == 'active')
                
                stats_text = f"邮箱数: {mailbox_count} | 激活: {active_count}"
                self.stats_label.setText(f"统计信息: {stats_text}")
            except Exception as e:
                self.stats_label.setText(f"统计信息: 获取失败 - {str(e)}")
                print(f"获取统计信息失败: {e}")  # 调试信息
                
        except Exception as e:
            QMessageBox.warning(self, "错误", f"刷新信息失败: {str(e)}")
    
    def get_default_settings(self):
        """获取默认设置"""
        return {
            'batch_size': self.default_batch_spin.value(),
            'delay': self.default_delay_spin.value(),
            'auto_save': self.auto_save_check.isChecked()
        }
    
    def clear_data(self):
        """清空数据"""
        self.user_info_label.setText("用户信息: 未登录")
        self.stats_label.setText("统计信息: 暂无数据")