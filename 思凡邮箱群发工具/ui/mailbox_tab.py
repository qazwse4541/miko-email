# -*- coding: utf-8 -*-
"""
邮箱管理选项卡
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QMessageBox, QInputDialog, QLineEdit, QComboBox,
                             QLabel, QTextEdit, QGroupBox, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

class MailboxTab(QWidget):
    """邮箱管理选项卡"""
    
    def __init__(self):
        super().__init__()
        self.api = None
        self.domains = []
        self.init_ui()
    
    def init_ui(self):
        """初始化UI"""
        layout = QVBoxLayout(self)
        
        # 创建分割器
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)
        
        # 左侧：邮箱列表
        self.create_mailbox_list(splitter)
        
        # 右侧：操作面板
        self.create_operation_panel(splitter)
        
        # 设置分割器比例
        splitter.setSizes([800, 400])
    
    def create_mailbox_list(self, parent):
        """创建邮箱列表"""
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # 标题和操作按钮
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("邮箱账号列表"))
        header_layout.addStretch()
        
        # 批量删除按钮
        self.batch_delete_btn = QPushButton("批量删除")
        self.batch_delete_btn.setProperty("class", "danger")
        self.batch_delete_btn.clicked.connect(self.batch_delete_mailboxes)
        header_layout.addWidget(self.batch_delete_btn)
        
        self.refresh_btn = QPushButton("刷新")
        self.refresh_btn.clicked.connect(self.refresh_mailboxes)
        header_layout.addWidget(self.refresh_btn)
        
        left_layout.addLayout(header_layout)
        
        # 邮箱表格
        self.mailbox_table = QTableWidget()
        self.mailbox_table.setColumnCount(6)
        self.mailbox_table.setHorizontalHeaderLabels([
            "邮箱地址", "域名", "状态", "邮件数", "创建时间", "操作"
        ])
        
        # 设置表格属性
        header = self.mailbox_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        
        # 设置多选模式
        self.mailbox_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.mailbox_table.setSelectionMode(QTableWidget.MultiSelection)
        self.mailbox_table.setAlternatingRowColors(True)
        
        left_layout.addWidget(self.mailbox_table)
        
        parent.addWidget(left_widget)
    
    def create_operation_panel(self, parent):
        """创建操作面板"""
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # 单个创建邮箱
        single_group = QGroupBox("创建单个邮箱")
        single_layout = QVBoxLayout(single_group)
        
        # 邮箱前缀
        prefix_layout = QHBoxLayout()
        prefix_layout.addWidget(QLabel("邮箱前缀:"))
        self.prefix_edit = QLineEdit()
        self.prefix_edit.setPlaceholderText("输入邮箱前缀")
        prefix_layout.addWidget(self.prefix_edit)
        single_layout.addLayout(prefix_layout)
        
        # 域名选择
        domain_layout = QHBoxLayout()
        domain_layout.addWidget(QLabel("选择域名:"))
        self.domain_combo = QComboBox()
        domain_layout.addWidget(self.domain_combo)
        single_layout.addLayout(domain_layout)
        
        # 密码
        password_layout = QHBoxLayout()
        password_layout.addWidget(QLabel("邮箱密码:"))
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("输入邮箱密码")
        password_layout.addWidget(self.password_edit)
        single_layout.addLayout(password_layout)
        
        # 创建按钮
        self.create_single_btn = QPushButton("创建邮箱")
        self.create_single_btn.setProperty("class", "success")
        self.create_single_btn.clicked.connect(self.create_single_mailbox)
        single_layout.addWidget(self.create_single_btn)
        
        right_layout.addWidget(single_group)
        
        # 批量创建邮箱
        batch_group = QGroupBox("批量创建邮箱")
        batch_layout = QVBoxLayout(batch_group)
        
        batch_layout.addWidget(QLabel("邮箱前缀列表 (每行一个):"))
        
        self.batch_text = QTextEdit()
        self.batch_text.setPlaceholderText("user1\nuser2\nuser3\n...")
        self.batch_text.setMaximumHeight(100)
        batch_layout.addWidget(self.batch_text)
        
        # 批量域名选择
        batch_domain_layout = QHBoxLayout()
        batch_domain_layout.addWidget(QLabel("选择域名:"))
        self.batch_domain_combo = QComboBox()
        batch_domain_layout.addWidget(self.batch_domain_combo)
        batch_layout.addLayout(batch_domain_layout)
        
        # 批量创建按钮
        self.create_batch_btn = QPushButton("批量创建")
        self.create_batch_btn.setProperty("class", "success")
        self.create_batch_btn.clicked.connect(self.create_batch_mailboxes)
        batch_layout.addWidget(self.create_batch_btn)
        
        right_layout.addWidget(batch_group)
        
        # 固定前缀批量创建
        prefix_batch_group = QGroupBox("固定前缀批量创建")
        prefix_batch_layout = QVBoxLayout(prefix_batch_group)
        
        # 固定前缀输入
        fixed_prefix_layout = QHBoxLayout()
        fixed_prefix_layout.addWidget(QLabel("固定前缀:"))
        self.fixed_prefix_edit = QLineEdit()
        self.fixed_prefix_edit.setPlaceholderText("如: kimi")
        fixed_prefix_layout.addWidget(self.fixed_prefix_edit)
        prefix_batch_layout.addLayout(fixed_prefix_layout)
        
        # 创建数量
        count_layout = QHBoxLayout()
        count_layout.addWidget(QLabel("创建数量:"))
        from PyQt5.QtWidgets import QSpinBox
        self.count_spin = QSpinBox()
        self.count_spin.setMinimum(1)
        self.count_spin.setMaximum(100)
        self.count_spin.setValue(10)
        count_layout.addWidget(self.count_spin)
        count_layout.addStretch()
        prefix_batch_layout.addLayout(count_layout)
        
        # 固定前缀域名选择
        prefix_domain_layout = QHBoxLayout()
        prefix_domain_layout.addWidget(QLabel("选择域名:"))
        self.prefix_domain_combo = QComboBox()
        prefix_domain_layout.addWidget(self.prefix_domain_combo)
        prefix_batch_layout.addLayout(prefix_domain_layout)
        
        # 预览
        preview_layout = QHBoxLayout()
        self.preview_label = QLabel("预览: kimi01@domain.com ~ kimi10@domain.com")
        self.preview_label.setStyleSheet("color: #666; font-size: 11px;")
        preview_layout.addWidget(self.preview_label)
        prefix_batch_layout.addLayout(preview_layout)
        
        # 固定前缀批量创建按钮
        self.create_prefix_batch_btn = QPushButton("批量创建邮箱")
        self.create_prefix_batch_btn.setProperty("class", "success")
        self.create_prefix_batch_btn.clicked.connect(self.create_prefix_batch_mailboxes)
        prefix_batch_layout.addWidget(self.create_prefix_batch_btn)
        
        # 连接信号以更新预览
        self.fixed_prefix_edit.textChanged.connect(self.update_preview)
        self.count_spin.valueChanged.connect(self.update_preview)
        
        right_layout.addWidget(prefix_batch_group)
        
        # 邮箱操作
        operation_group = QGroupBox("邮箱操作")
        operation_layout = QVBoxLayout(operation_group)
        
        self.get_password_btn = QPushButton("获取密码")
        self.get_password_btn.clicked.connect(self.get_mailbox_password)
        operation_layout.addWidget(self.get_password_btn)
        
        self.delete_btn = QPushButton("删除邮箱")
        self.delete_btn.setProperty("class", "danger")
        self.delete_btn.clicked.connect(self.delete_mailbox)
        operation_layout.addWidget(self.delete_btn)
        
        right_layout.addWidget(operation_group)
        
        right_layout.addStretch()
        
        parent.addWidget(right_widget)
    
    def set_api(self, api):
        """设置API客户端"""
        self.api = api
        self.load_domains()
        self.refresh_mailboxes()
        
        # 通知发送选项卡更新邮箱列表
        main_window = self.parent()
        while main_window and not hasattr(main_window, 'compose_tab'):
            main_window = main_window.parent()
        
        if main_window and hasattr(main_window, 'compose_tab'):
            main_window.compose_tab.load_mailboxes()
    
    def load_domains(self):
        """加载域名列表"""
        if not self.api:
            return
        
        try:
            self.domains = self.api.get_available_domains()
            
            # 更新域名下拉框
            self.domain_combo.clear()
            self.batch_domain_combo.clear()
            self.prefix_domain_combo.clear()
            
            for domain in self.domains:
                domain_text = f"{domain['name']} (ID: {domain['id']})"
                self.domain_combo.addItem(domain_text, domain['id'])
                self.batch_domain_combo.addItem(domain_text, domain['id'])
                self.prefix_domain_combo.addItem(domain_text, domain['id'])
            
            # 更新预览
            self.update_preview()
                
        except Exception as e:
            QMessageBox.warning(self, "错误", f"加载域名失败: {str(e)}")
    
    def refresh_mailboxes(self):
        """刷新邮箱列表"""
        if not self.api:
            return
        
        try:
            mailboxes = self.api.get_mailboxes()
            
            self.mailbox_table.setRowCount(len(mailboxes))
            
            for row, mailbox in enumerate(mailboxes):
                # 邮箱地址
                address = mailbox.get('email', '')
                self.mailbox_table.setItem(row, 0, QTableWidgetItem(address))
                
                # 域名 - 从邮箱地址中提取
                domain = address.split('@')[1] if '@' in address else ''
                self.mailbox_table.setItem(row, 1, QTableWidgetItem(domain))
                
                # 状态
                status_value = mailbox.get('status', 'active')
                status = "正常" if status_value == 'active' else "禁用"
                self.mailbox_table.setItem(row, 2, QTableWidgetItem(status))
                
                # 邮件数 - 暂时显示为0，因为API返回中没有这个字段
                self.mailbox_table.setItem(row, 3, QTableWidgetItem("0"))
                
                # 创建时间
                created_at = mailbox.get('created_at', '')
                if created_at and 'T' in created_at:
                    created_at = created_at.split('T')[0]  # 只显示日期
                self.mailbox_table.setItem(row, 4, QTableWidgetItem(created_at))
                
                # 操作按钮
                mailbox_id = mailbox.get('id', '')
                self.mailbox_table.setItem(row, 5, QTableWidgetItem(f"ID: {mailbox_id}"))
                
        except Exception as e:
            QMessageBox.warning(self, "错误", f"刷新邮箱列表失败: {str(e)}")
            print(f"邮箱数据结构: {mailboxes}")  # 调试信息
    
    def create_single_mailbox(self):
        """创建单个邮箱"""
        prefix = self.prefix_edit.text().strip()
        password = self.password_edit.text().strip()
        
        if not prefix:
            QMessageBox.warning(self, "错误", "请输入邮箱前缀")
            return
        
        if not password:
            QMessageBox.warning(self, "错误", "请输入邮箱密码")
            return
        
        domain_id = self.domain_combo.currentData()
        if domain_id is None:
            QMessageBox.warning(self, "错误", "请选择域名")
            return
        
        try:
            response = self.api.create_mailbox(prefix, domain_id, password)
            QMessageBox.information(self, "成功", "邮箱创建成功！")
            
            # 清空输入框
            self.prefix_edit.clear()
            self.password_edit.clear()
            
            # 刷新列表
            self.refresh_mailboxes()
            
            # 刷新发送选项卡的邮箱列表
            self.update_compose_tab_mailboxes()
            
        except Exception as e:
            QMessageBox.warning(self, "错误", f"创建邮箱失败: {str(e)}")
    
    def create_batch_mailboxes(self):
        """批量创建邮箱"""
        prefixes_text = self.batch_text.toPlainText().strip()
        if not prefixes_text:
            QMessageBox.warning(self, "错误", "请输入邮箱前缀列表")
            return
        
        prefixes = [p.strip() for p in prefixes_text.split('\n') if p.strip()]
        if not prefixes:
            QMessageBox.warning(self, "错误", "请输入有效的邮箱前缀")
            return
        
        domain_id = self.batch_domain_combo.currentData()
        if domain_id is None:
            QMessageBox.warning(self, "错误", "请选择域名")
            return
        
        try:
            response = self.api.create_mailboxes_batch(prefixes, domain_id)
            
            # 检查响应数据结构
            data = response.get('data', [])
            
            if isinstance(data, list):
                # 新的API返回格式：data是邮箱列表
                success_count = len(data)
                failed_count = len(prefixes) - success_count
                
                message = f"批量创建完成！\n成功: {success_count} 个\n失败: {failed_count} 个"
                
                if success_count > 0:
                    message += f"\n\n成功创建的邮箱:\n"
                    for mailbox in data:
                        email = mailbox.get('email', '')
                        message += f"- {email}\n"
                
            else:
                # 旧的API返回格式：data是对象
                success_count = len(data.get('created', []))
                failed_count = len(data.get('failed', []))
                
                message = f"批量创建完成！\n成功: {success_count} 个\n失败: {failed_count} 个"
                
                if failed_count > 0:
                    failed_list = data.get('failed', [])
                    message += f"\n\n失败的邮箱:\n" + '\n'.join([f"{f.get('prefix', '')}: {f.get('error', '')}" for f in failed_list])
            
            QMessageBox.information(self, "批量创建结果", message)
            
            # 清空输入框
            self.batch_text.clear()
            
            # 刷新列表
            self.refresh_mailboxes()
            
            # 刷新发送选项卡的邮箱列表
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'compose_tab'):
                main_window = main_window.parent()
            
            if main_window and hasattr(main_window, 'compose_tab'):
                main_window.compose_tab.load_mailboxes()
            
        except Exception as e:
            QMessageBox.warning(self, "错误", f"批量创建邮箱失败: {str(e)}")
            print(f"批量创建错误详情: {e}")  # 调试信息
    
    def get_mailbox_password(self):
        """获取邮箱密码"""
        current_row = self.mailbox_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "错误", "请选择一个邮箱")
            return
        
        # 从操作列获取邮箱ID
        id_item = self.mailbox_table.item(current_row, 5)
        if not id_item:
            QMessageBox.warning(self, "错误", "无法获取邮箱ID")
            return
        
        try:
            mailbox_id = int(id_item.text().replace("ID: ", ""))
            password = self.api.get_mailbox_password(mailbox_id)
            
            mailbox_address = self.mailbox_table.item(current_row, 0).text()
            QMessageBox.information(self, "邮箱密码", 
                                  f"邮箱: {mailbox_address}\n密码: {password}")
            
        except Exception as e:
            QMessageBox.warning(self, "错误", f"获取邮箱密码失败: {str(e)}")
    
    def delete_mailbox(self):
        """删除邮箱"""
        current_row = self.mailbox_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "错误", "请选择一个邮箱")
            return
        
        mailbox_address = self.mailbox_table.item(current_row, 0).text()
        
        reply = QMessageBox.question(self, "确认删除", 
                                   f"确定要删除邮箱 {mailbox_address} 吗？\n此操作不可恢复！",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply != QMessageBox.Yes:
            return
        
        # 从操作列获取邮箱ID
        id_item = self.mailbox_table.item(current_row, 5)
        if not id_item:
            QMessageBox.warning(self, "错误", "无法获取邮箱ID")
            return
        
        try:
            mailbox_id = int(id_item.text().replace("ID: ", ""))
            self.api.delete_mailbox(mailbox_id)
            
            QMessageBox.information(self, "成功", "邮箱删除成功！")
            
            # 刷新列表
            self.refresh_mailboxes()
            
            # 刷新发送选项卡的邮箱列表
            self.update_compose_tab_mailboxes()
            
        except Exception as e:
            QMessageBox.warning(self, "错误", f"删除邮箱失败: {str(e)}")
    
    def batch_delete_mailboxes(self):
        """批量删除邮箱"""
        selected_rows = []
        for i in range(self.mailbox_table.rowCount()):
            if self.mailbox_table.item(i, 0).isSelected():
                selected_rows.append(i)
        
        if not selected_rows:
            QMessageBox.warning(self, "错误", "请选择要删除的邮箱")
            return
        
        # 获取选中的邮箱信息
        selected_emails = []
        selected_ids = []
        
        for row in selected_rows:
            email_item = self.mailbox_table.item(row, 0)
            id_item = self.mailbox_table.item(row, 5)
            
            if email_item and id_item:
                selected_emails.append(email_item.text())
                try:
                    mailbox_id = int(id_item.text().replace("ID: ", ""))
                    selected_ids.append(mailbox_id)
                except ValueError:
                    continue
        
        if not selected_ids:
            QMessageBox.warning(self, "错误", "无法获取选中邮箱的ID")
            return
        
        # 确认删除
        email_list = '\n'.join(selected_emails[:10])  # 最多显示10个
        if len(selected_emails) > 10:
            email_list += f'\n... 还有 {len(selected_emails) - 10} 个邮箱'
        
        reply = QMessageBox.question(self, "确认批量删除", 
                                   f"确定要删除以下 {len(selected_emails)} 个邮箱吗？\n\n{email_list}\n\n此操作不可恢复！",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply != QMessageBox.Yes:
            return
        
        # 执行批量删除
        success_count = 0
        failed_count = 0
        failed_emails = []
        
        for i, mailbox_id in enumerate(selected_ids):
            try:
                self.api.delete_mailbox(mailbox_id)
                success_count += 1
            except Exception as e:
                failed_count += 1
                failed_emails.append(f"{selected_emails[i]}: {str(e)}")
        
        # 显示结果
        message = f"批量删除完成！\n成功: {success_count} 个\n失败: {failed_count} 个"
        
        if failed_count > 0:
            message += f"\n\n失败的邮箱:\n" + '\n'.join(failed_emails[:5])
            if len(failed_emails) > 5:
                message += f"\n... 还有 {len(failed_emails) - 5} 个失败"
        
        QMessageBox.information(self, "批量删除结果", message)
        
        # 刷新列表
        self.refresh_mailboxes()
        
        # 刷新发送选项卡的邮箱列表
        self.update_compose_tab_mailboxes()
    
    def update_preview(self):
        """更新预览"""
        prefix = self.fixed_prefix_edit.text().strip()
        count = self.count_spin.value()
        
        if not prefix:
            self.preview_label.setText("预览: 请输入前缀")
            return
        
        # 获取当前选择的域名
        domain_name = "domain.com"
        if self.prefix_domain_combo.count() > 0:
            current_text = self.prefix_domain_combo.currentText()
            if " (ID:" in current_text:
                domain_name = current_text.split(" (ID:")[0]
        
        # 生成预览
        if count == 1:
            preview_text = f"预览: {prefix}01@{domain_name}"
        else:
            start_email = f"{prefix}01@{domain_name}"
            end_email = f"{prefix}{count:02d}@{domain_name}"
            preview_text = f"预览: {start_email} ~ {end_email}"
        
        self.preview_label.setText(preview_text)
    
    def create_prefix_batch_mailboxes(self):
        """固定前缀批量创建邮箱"""
        prefix = self.fixed_prefix_edit.text().strip()
        count = self.count_spin.value()
        
        if not prefix:
            QMessageBox.warning(self, "错误", "请输入固定前缀")
            return
        
        domain_id = self.prefix_domain_combo.currentData()
        if domain_id is None:
            QMessageBox.warning(self, "错误", "请选择域名")
            return
        
        # 生成邮箱前缀列表
        prefixes = []
        for i in range(1, count + 1):
            prefixes.append(f"{prefix}{i:02d}")
        
        # 获取域名用于预览
        domain_name = "domain.com"
        if self.prefix_domain_combo.count() > 0:
            current_text = self.prefix_domain_combo.currentText()
            if " (ID:" in current_text:
                domain_name = current_text.split(" (ID:")[0]
        
        # 确认创建
        preview_emails = [f"{p}@{domain_name}" for p in prefixes[:5]]
        preview_text = '\n'.join(preview_emails)
        if count > 5:
            preview_text += f'\n... 还有 {count - 5} 个邮箱'
        
        reply = QMessageBox.question(self, "确认批量创建", 
                                   f"确定要创建以下 {count} 个邮箱吗？\n\n{preview_text}",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply != QMessageBox.Yes:
            return
        
        try:
            response = self.api.create_mailboxes_batch(prefixes, domain_id)
            
            # 检查响应数据结构
            data = response.get('data', [])
            
            if isinstance(data, list):
                # 新的API返回格式：data是邮箱列表
                success_count = len(data)
                failed_count = len(prefixes) - success_count
                
                message = f"固定前缀批量创建完成！\n成功: {success_count} 个\n失败: {failed_count} 个"
                
                if success_count > 0:
                    message += f"\n\n成功创建的邮箱:\n"
                    for mailbox in data[:10]:  # 最多显示10个
                        email = mailbox.get('email', '')
                        message += f"- {email}\n"
                    if len(data) > 10:
                        message += f"... 还有 {len(data) - 10} 个邮箱"
                
            else:
                # 旧的API返回格式：data是对象
                success_count = len(data.get('created', []))
                failed_count = len(data.get('failed', []))
                
                message = f"固定前缀批量创建完成！\n成功: {success_count} 个\n失败: {failed_count} 个"
                
                if failed_count > 0:
                    failed_list = data.get('failed', [])
                    message += f"\n\n失败的邮箱:\n" + '\n'.join([f"{f.get('prefix', '')}: {f.get('error', '')}" for f in failed_list[:5]])
                    if len(failed_list) > 5:
                        message += f"\n... 还有 {len(failed_list) - 5} 个失败"
            
            QMessageBox.information(self, "批量创建结果", message)
            
            # 清空输入框
            self.fixed_prefix_edit.clear()
            
            # 刷新列表
            self.refresh_mailboxes()
            
            # 刷新发送选项卡的邮箱列表
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'compose_tab'):
                main_window = main_window.parent()
            
            if main_window and hasattr(main_window, 'compose_tab'):
                main_window.compose_tab.load_mailboxes()
            
        except Exception as e:
            QMessageBox.warning(self, "错误", f"固定前缀批量创建邮箱失败: {str(e)}")
            print(f"固定前缀批量创建错误详情: {e}")  # 调试信息
    
    def update_compose_tab_mailboxes(self):
        """更新发送选项卡的邮箱列表"""
        try:
            # 获取主窗口
            main_window = self.parent()
            while main_window and not hasattr(main_window, 'compose_tab'):
                main_window = main_window.parent()
            
            if main_window and hasattr(main_window, 'compose_tab'):
                # 刷新发送选项卡的邮箱列表
                main_window.compose_tab.load_mailboxes()
                print("已更新发送选项卡的邮箱列表")  # 调试信息
            else:
                print("无法找到发送选项卡")  # 调试信息
        except Exception as e:
            print(f"更新发送选项卡邮箱列表失败: {e}")  # 调试信息
    
    def clear_data(self):
        """清空数据"""
        self.mailbox_table.setRowCount(0)
        self.domain_combo.clear()
        self.batch_domain_combo.clear()
        self.prefix_domain_combo.clear()
        self.prefix_edit.clear()
        self.password_edit.clear()
        self.batch_text.clear()
        self.fixed_prefix_edit.clear()
        self.preview_label.setText("预览: 请输入前缀")