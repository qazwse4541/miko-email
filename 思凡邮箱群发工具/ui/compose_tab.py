# -*- coding: utf-8 -*-
"""
邮件发送选项卡
"""

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QTextEdit, QLineEdit, QLabel, QComboBox, QGroupBox,
                             QTableWidget, QTableWidgetItem, QHeaderView,
                             QMessageBox, QProgressBar, QSplitter, QSpinBox,
                             QCheckBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QMutex
from PyQt5.QtGui import QFont
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class EmailSendThread(QThread):
    """邮件发送线程"""
    
    progress_updated = pyqtSignal(int, int, str)  # 当前进度, 总数, 状态信息
    send_completed = pyqtSignal(int, int)  # 成功数, 失败数
    
    def __init__(self, api, from_email, to_emails, subject, content, batch_size=1, delay=0, repeat_count=1, is_html=False):
        super().__init__()
        self.api = api
        self.from_email = from_email
        self.to_emails = to_emails
        self.subject = subject
        self.content = content
        self.batch_size = batch_size
        self.delay = delay
        self.repeat_count = repeat_count
        self.is_html = is_html
        self.is_running = True
    
    def run(self):
        """运行发送任务"""
        success_count = 0
        failed_count = 0
        
        # 计算总发送数量：收件人数量 × 重复次数
        total_count = len(self.to_emails) * self.repeat_count
        current_progress = 0
        
        # 重复发送
        for repeat_idx in range(self.repeat_count):
            if not self.is_running:
                break
            
            self.progress_updated.emit(current_progress, total_count, 
                                     f"第 {repeat_idx + 1}/{self.repeat_count} 轮发送...")
            
            # 按批次发送
            for i in range(0, len(self.to_emails), self.batch_size):
                if not self.is_running:
                    break
                
                batch_emails = self.to_emails[i:i + self.batch_size]
                
                try:
                    current_progress += len(batch_emails)
                    self.progress_updated.emit(current_progress, total_count, 
                                             f"第 {repeat_idx + 1} 轮：发送第 {i+1}-{min(i+self.batch_size, len(self.to_emails))} 封邮件...")
                    
                    # 发送邮件
                    result = self.api.send_email(
                        from_email=self.from_email,
                        to_emails=batch_emails,
                        subject=self.subject,
                        content=self.content,
                        is_html=self.is_html
                    )
                    
                    success_count += len(batch_emails)
                    print(f"发送成功: {batch_emails} -> {result}")  # 调试信息
                    
                except Exception as e:
                    failed_count += len(batch_emails)
                    print(f"发送失败: {batch_emails} -> {str(e)}")  # 调试信息
                    self.progress_updated.emit(current_progress, total_count, 
                                             f"第 {repeat_idx + 1} 轮发送失败: {str(e)}")
                
                # 延时
                if self.delay > 0 and (i + self.batch_size < len(self.to_emails) or repeat_idx < self.repeat_count - 1):
                    time.sleep(self.delay)
        
        self.send_completed.emit(success_count, failed_count)
    
    def stop(self):
        """停止发送"""
        self.is_running = False

class ConcurrentEmailThread(QThread):
    """并发邮件发送线程"""
    
    progress_updated = pyqtSignal(int, int, str)  # 当前进度, 总数, 状态信息
    send_completed = pyqtSignal(int, int)  # 成功数, 失败数
    
    def __init__(self, api, from_email, to_emails, subject, content, concurrent_threads=1, delay=0, repeat_count=1, is_html=False):
        super().__init__()
        self.api = api
        self.from_email = from_email
        self.to_emails = to_emails
        self.subject = subject
        self.content = content
        self.concurrent_threads = concurrent_threads
        self.delay = delay
        self.repeat_count = repeat_count
        self.is_html = is_html
        self.is_running = True
        self.mutex = QMutex()
        self.success_count = 0
        self.failed_count = 0
        self.current_progress = 0
    
    def send_single_email(self, to_email, repeat_idx=0):
        """发送单封邮件"""
        try:
            # 发送邮件
            self.api.send_email(
                from_email=self.from_email,
                to_emails=[to_email],
                subject=self.subject,
                content=self.content,
                is_html=self.is_html
            )
            
            # 线程安全地更新计数
            self.mutex.lock()
            self.success_count += 1
            self.current_progress += 1
            current = self.current_progress
            self.mutex.unlock()
            
            # 发送进度更新信号
            total_count = len(self.to_emails) * self.repeat_count
            self.progress_updated.emit(current, total_count, 
                                     f"第 {repeat_idx + 1} 轮：成功发送到 {to_email}")
            
            return True
            
        except Exception as e:
            # 线程安全地更新计数
            self.mutex.lock()
            self.failed_count += 1
            self.current_progress += 1
            current = self.current_progress
            self.mutex.unlock()
            
            # 发送进度更新信号
            total_count = len(self.to_emails) * self.repeat_count
            self.progress_updated.emit(current, total_count, 
                                     f"第 {repeat_idx + 1} 轮：发送失败 {to_email} - {str(e)}")
            
            print(f"发送失败: {to_email} -> {str(e)}")  # 调试信息
            return False
    
    def run(self):
        """运行并发发送任务"""
        self.success_count = 0
        self.failed_count = 0
        self.current_progress = 0
        
        # 计算总发送数量：收件人数量 × 重复次数
        total_count = len(self.to_emails) * self.repeat_count
        
        # 重复发送
        for repeat_idx in range(self.repeat_count):
            if not self.is_running:
                break
            
            self.progress_updated.emit(self.current_progress, total_count, 
                                     f"第 {repeat_idx + 1}/{self.repeat_count} 轮并发发送...")
            
            # 使用线程池进行并发发送
            with ThreadPoolExecutor(max_workers=self.concurrent_threads) as executor:
                # 提交所有发送任务
                future_to_email = {
                    executor.submit(self.send_single_email, email, repeat_idx): email 
                    for email in self.to_emails
                }
                
                # 等待所有任务完成
                for future in as_completed(future_to_email):
                    if not self.is_running:
                        # 如果停止发送，取消所有未完成的任务
                        for f in future_to_email:
                            f.cancel()
                        break
                    
                    email = future_to_email[future]
                    try:
                        result = future.result()
                    except Exception as e:
                        print(f"任务执行异常: {email} -> {str(e)}")
            
            # 批次间延时
            if self.delay > 0 and repeat_idx < self.repeat_count - 1 and self.is_running:
                time.sleep(self.delay)
        
        self.send_completed.emit(self.success_count, self.failed_count)
    
    def stop(self):
        """停止发送"""
        self.is_running = False

class MultiSenderEmailThread(QThread):
    """多发件人邮件发送线程"""
    
    progress_updated = pyqtSignal(int, int, str)  # 当前进度, 总数, 状态信息
    send_completed = pyqtSignal(int, int)  # 成功数, 失败数
    
    def __init__(self, api, from_emails, to_emails, subject, content, batch_size=1, delay=0, concurrent_threads=1, is_html=False):
        super().__init__()
        self.api = api
        self.from_emails = from_emails  # 发件人邮箱列表
        self.to_emails = to_emails
        self.subject = subject
        self.content = content
        self.batch_size = batch_size
        self.delay = delay
        self.concurrent_threads = concurrent_threads
        self.is_html = is_html
        self.is_running = True
        self.mutex = QMutex()
        self.success_count = 0
        self.failed_count = 0
        self.current_progress = 0
    
    def send_single_email_multi_sender(self, from_email, to_email):
        """多发件人发送单封邮件"""
        try:
            # 发送邮件
            self.api.send_email(
                from_email=from_email,
                to_emails=[to_email],
                subject=self.subject,
                content=self.content,
                is_html=self.is_html
            )
            
            # 线程安全地更新计数
            self.mutex.lock()
            self.success_count += 1
            self.current_progress += 1
            current = self.current_progress
            self.mutex.unlock()
            
            # 发送进度更新信号
            total_count = len(self.to_emails) * len(self.from_emails)
            self.progress_updated.emit(current, total_count, 
                                     f"发件人 {from_email} 成功发送到 {to_email}")
            
            return True
            
        except Exception as e:
            # 线程安全地更新计数
            self.mutex.lock()
            self.failed_count += 1
            self.current_progress += 1
            current = self.current_progress
            self.mutex.unlock()
            
            # 发送进度更新信号
            total_count = len(self.to_emails) * len(self.from_emails)
            self.progress_updated.emit(current, total_count, 
                                     f"发件人 {from_email} 发送失败到 {to_email} - {str(e)}")
            
            print(f"发送失败: {from_email} -> {to_email} -> {str(e)}")  # 调试信息
            return False
    
    def run(self):
        """运行多发件人并发发送任务"""
        self.success_count = 0
        self.failed_count = 0
        self.current_progress = 0
        
        # 计算总发送数量：每个收件人 × 每个发件人
        total_count = len(self.to_emails) * len(self.from_emails)
        
        self.progress_updated.emit(0, total_count, "开始多发件人并发发送...")
        
        # 创建所有发送任务
        tasks = []
        for from_email in self.from_emails:
            for to_email in self.to_emails:
                tasks.append((from_email, to_email))
        
        # 使用线程池进行并发发送
        with ThreadPoolExecutor(max_workers=self.concurrent_threads) as executor:
            # 提交所有发送任务
            future_to_task = {
                executor.submit(self.send_single_email_multi_sender, from_email, to_email): (from_email, to_email)
                for from_email, to_email in tasks
            }
            
            # 等待所有任务完成
            for future in as_completed(future_to_task):
                if not self.is_running:
                    # 如果停止发送，取消所有未完成的任务
                    for f in future_to_task:
                        f.cancel()
                    break
                
                from_email, to_email = future_to_task[future]
                try:
                    result = future.result()
                except Exception as e:
                    print(f"任务执行异常: {from_email} -> {to_email} -> {str(e)}")
                
                # 延时控制
                if self.delay > 0:
                    time.sleep(self.delay / self.concurrent_threads)  # 根据并发数调整延时
        
        self.send_completed.emit(self.success_count, self.failed_count)
    
    def stop(self):
        """停止发送"""
        self.is_running = False

class ComposeTab(QWidget):
    """邮件发送选项卡"""
    
    def __init__(self):
        super().__init__()
        self.api = None
        self.mailboxes = []
        self.send_thread = None
        self.init_ui()
    
    def init_ui(self):
        """初始化UI"""
        layout = QVBoxLayout(self)
        
        # 创建分割器
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)
        
        # 左侧：邮件编辑
        self.create_compose_panel(splitter)
        
        # 右侧：发送状态
        self.create_status_panel(splitter)
        
        # 设置分割器比例
        splitter.setSizes([800, 400])
    
    def create_compose_panel(self, parent):
        """创建邮件编辑面板"""
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        
        # 邮件信息
        info_group = QGroupBox("邮件信息")
        info_layout = QVBoxLayout(info_group)
        
        # 发件人
        from_layout = QHBoxLayout()
        from_layout.addWidget(QLabel("发件人:"))
        self.from_combo = QComboBox()
        self.from_combo.setEditable(False)
        from_layout.addWidget(self.from_combo)
        
        # 添加刷新按钮
        self.refresh_mailbox_btn = QPushButton("🔄")
        self.refresh_mailbox_btn.setMaximumWidth(30)
        self.refresh_mailbox_btn.setToolTip("刷新邮箱列表")
        self.refresh_mailbox_btn.clicked.connect(self.load_mailboxes)
        from_layout.addWidget(self.refresh_mailbox_btn)
        
        info_layout.addLayout(from_layout)
        
        # 收件人
        to_layout = QVBoxLayout()
        to_layout.addWidget(QLabel("收件人列表 (每行一个邮箱地址):"))
        self.to_text = QTextEdit()
        self.to_text.setPlaceholderText("user1@example.com\nuser2@example.com\n...")
        self.to_text.setMaximumHeight(120)
        to_layout.addWidget(self.to_text)
        info_layout.addLayout(to_layout)
        
        # 邮件主题
        subject_layout = QHBoxLayout()
        subject_layout.addWidget(QLabel("邮件主题:"))
        self.subject_edit = QLineEdit()
        self.subject_edit.setPlaceholderText("请输入邮件主题")
        subject_layout.addWidget(self.subject_edit)
        info_layout.addLayout(subject_layout)
        
        left_layout.addWidget(info_group)
        
        # 邮件内容
        content_group = QGroupBox("邮件内容")
        content_layout = QVBoxLayout(content_group)
        
        # 添加HTML选项
        html_option_layout = QHBoxLayout()
        self.html_checkbox = QCheckBox("HTML格式邮件")
        self.html_checkbox.setToolTip("勾选后将以HTML格式发送邮件")
        html_option_layout.addWidget(self.html_checkbox)
        
        self.preview_btn = QPushButton("预览HTML效果")
        self.preview_btn.clicked.connect(self.preview_html)
        html_option_layout.addWidget(self.preview_btn)
        
        self.template_btn = QPushButton("加载HTML模板")
        self.template_btn.clicked.connect(self.load_html_template)
        html_option_layout.addWidget(self.template_btn)
        
        html_option_layout.addStretch()
        content_layout.addLayout(html_option_layout)
        
        self.content_text = QTextEdit()
        self.content_text.setPlaceholderText("请输入邮件内容...\n如果勾选了HTML格式，可以在此输入HTML代码")
        content_layout.addWidget(self.content_text)
        
        left_layout.addWidget(content_group)
        
        # 发送设置
        settings_group = QGroupBox("发送设置")
        settings_layout = QVBoxLayout(settings_group)
        
        # 批次设置
        batch_layout = QHBoxLayout()
        batch_layout.addWidget(QLabel("每批发送数量:"))
        self.batch_spin = QSpinBox()
        self.batch_spin.setMinimum(1)
        self.batch_spin.setMaximum(100)
        self.batch_spin.setValue(1)
        batch_layout.addWidget(self.batch_spin)
        batch_layout.addStretch()
        settings_layout.addLayout(batch_layout)
        
        # 延时设置
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("批次间延时(秒):"))
        self.delay_spin = QSpinBox()
        self.delay_spin.setMinimum(0)
        self.delay_spin.setMaximum(60)
        self.delay_spin.setValue(0)
        delay_layout.addWidget(self.delay_spin)
        delay_layout.addStretch()
        settings_layout.addLayout(delay_layout)
        
        # 重复发送次数
        repeat_layout = QHBoxLayout()
        repeat_layout.addWidget(QLabel("重复发送次数:"))
        self.repeat_spin = QSpinBox()
        self.repeat_spin.setMinimum(1)
        self.repeat_spin.setMaximum(10)
        self.repeat_spin.setValue(1)
        self.repeat_spin.setToolTip("设置向同一收件人重复发送的次数")
        repeat_layout.addWidget(self.repeat_spin)
        repeat_layout.addStretch()
        settings_layout.addLayout(repeat_layout)
        
        # 并发线程数设置
        concurrent_layout = QHBoxLayout()
        concurrent_layout.addWidget(QLabel("并发线程数:"))
        self.concurrent_spin = QSpinBox()
        self.concurrent_spin.setMinimum(1)
        self.concurrent_spin.setMaximum(20)
        self.concurrent_spin.setValue(3)
        self.concurrent_spin.setToolTip("同时发送邮件的线程数，建议3-10个，过多可能被限制")
        concurrent_layout.addWidget(self.concurrent_spin)
        
        # 添加说明标签
        concurrent_info = QLabel("(推荐3-5个)")
        concurrent_info.setStyleSheet("color: #666; font-size: 11px;")
        concurrent_layout.addWidget(concurrent_info)
        concurrent_layout.addStretch()
        settings_layout.addLayout(concurrent_layout)
        
        left_layout.addWidget(settings_group)
        
        # 发送按钮
        button_layout = QHBoxLayout()
        
        self.send_btn = QPushButton("开始发送")
        self.send_btn.setProperty("class", "success")
        self.send_btn.clicked.connect(self.start_sending)
        button_layout.addWidget(self.send_btn)
        
        self.stop_btn = QPushButton("停止发送")
        self.stop_btn.setProperty("class", "danger")
        self.stop_btn.clicked.connect(self.stop_sending)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        button_layout.addStretch()
        
        left_layout.addLayout(button_layout)
        
        parent.addWidget(left_widget)
    
    def create_status_panel(self, parent):
        """创建发送状态面板"""
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # 发送进度
        progress_group = QGroupBox("发送进度")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("就绪")
        progress_layout.addWidget(self.status_label)
        
        right_layout.addWidget(progress_group)
        
        # 发送统计
        stats_group = QGroupBox("发送统计")
        stats_layout = QVBoxLayout(stats_group)
        
        self.total_label = QLabel("总数: 0")
        stats_layout.addWidget(self.total_label)
        
        self.success_label = QLabel("成功: 0")
        stats_layout.addWidget(self.success_label)
        
        self.failed_label = QLabel("失败: 0")
        stats_layout.addWidget(self.failed_label)
        
        right_layout.addWidget(stats_group)
        
        # 发送历史
        history_group = QGroupBox("发送历史")
        history_layout = QVBoxLayout(history_group)
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels([
            "时间", "收件人", "主题", "状态"
        ])
        
        # 设置表格属性
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setMaximumHeight(200)
        
        history_layout.addWidget(self.history_table)
        
        right_layout.addWidget(history_group)
        
        right_layout.addStretch()
        
        parent.addWidget(right_widget)
    
    def set_api(self, api):
        """设置API客户端"""
        self.api = api
        self.load_mailboxes()
    
    def load_mailboxes(self):
        """加载邮箱列表"""
        if not self.api:
            print("API客户端未设置，无法加载邮箱列表")
            return
        
        try:
            print("开始加载邮箱列表...")
            self.mailboxes = self.api.get_mailboxes()
            print(f"从API获取到 {len(self.mailboxes)} 个邮箱")
            
            # 更新发件人下拉框
            self.from_combo.clear()
            
            # 获取激活的邮箱
            active_mailboxes = []
            disabled_mailboxes = []
            
            for mailbox in self.mailboxes:
                # 获取邮箱地址
                address = mailbox.get('email', '')
                
                if address:  # 确保地址有效
                    # 检查邮箱状态
                    status = mailbox.get('status', 'active')
                    
                    if status == 'active':
                        active_mailboxes.append(address)
                        self.from_combo.addItem(address)
                    else:
                        disabled_mailboxes.append(address)
                        self.from_combo.addItem(f"{address} (禁用)")
            
            print(f"激活邮箱: {len(active_mailboxes)} 个")
            print(f"禁用邮箱: {len(disabled_mailboxes)} 个")
            
            # 如果有多个激活邮箱，添加"全部邮箱"选项并设为默认
            if len(active_mailboxes) > 1:
                all_mailbox_text = f"🔄 全部邮箱 ({len(active_mailboxes)}个)"
                self.from_combo.insertItem(0, all_mailbox_text)
                # 设置默认选中"全部邮箱"
                self.from_combo.setCurrentIndex(0)
                print(f"添加了全部邮箱选项: {all_mailbox_text}")
            elif len(active_mailboxes) == 1:
                # 如果只有一个邮箱，默认选中它
                self.from_combo.setCurrentIndex(0)
                print("只有一个激活邮箱，设为默认选中")
            elif len(active_mailboxes) == 0:
                print("没有激活的邮箱")
            
            print(f"邮箱列表更新完成，下拉框共有 {self.from_combo.count()} 个选项")
                    
        except Exception as e:
            error_msg = f"加载邮箱列表失败: {str(e)}"
            print(error_msg)
            QMessageBox.warning(self, "错误", error_msg)
            print(f"邮箱数据结构: {self.mailboxes if hasattr(self, 'mailboxes') else '未获取到数据'}")  # 调试信息
    
    def preview_html(self):
        """预览HTML邮件效果"""
        content = self.content_text.toPlainText().strip()
        if not content:
            QMessageBox.warning(self, "错误", "请先输入HTML内容")
            return
        
        # 如果内容不是以<!DOCTYPE html>或<html>开头，添加基本HTML结构
        if not content.lower().startswith(("<!doctype html", "<html")):
            content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HTML邮件预览</title>
</head>
<body>
    {content}
</body>
</html>"""
        
        # 创建临时HTML文件
        import tempfile
        import os
        import webbrowser
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w', encoding='utf-8') as f:
            f.write(content)
            temp_path = f.name
        
        # 在浏览器中打开预览
        webbrowser.open('file://' + os.path.abspath(temp_path))
    
    def load_html_template(self):
        """加载HTML模板"""
        # 获取主窗口的设置选项卡
        main_window = self.parent()
        while main_window and not hasattr(main_window, 'settings_tab'):
            main_window = main_window.parent()
        
        if main_window and hasattr(main_window, 'settings_tab'):
            # 切换到设置选项卡
            main_window.tab_widget.setCurrentWidget(main_window.settings_tab)
            
            # 提示用户选择HTML模板
            QMessageBox.information(self, "提示", "请在设置选项卡中选择HTML模板，然后点击'应用到发送页面'按钮")
        else:
            QMessageBox.warning(self, "错误", "无法找到设置页面")
    
    def start_sending(self):
        """开始发送邮件"""
        # 验证输入
        from_email = self.from_combo.currentText().strip()
        if not from_email:
            QMessageBox.warning(self, "错误", "请选择发件人")
            return
        
        to_emails_text = self.to_text.toPlainText().strip()
        if not to_emails_text:
            QMessageBox.warning(self, "错误", "请输入收件人列表")
            return
        
        subject = self.subject_edit.text().strip()
        if not subject:
            QMessageBox.warning(self, "错误", "请输入邮件主题")
            return
        
        content = self.content_text.toPlainText().strip()
        if not content:
            QMessageBox.warning(self, "错误", "请输入邮件内容")
            return
        
        # 获取是否为HTML邮件
        is_html = self.html_checkbox.isChecked()
        
        # 解析收件人列表
        to_emails = [email.strip() for email in to_emails_text.split('\n') if email.strip()]
        if not to_emails:
            QMessageBox.warning(self, "错误", "请输入有效的收件人邮箱")
            return
        
        # 获取发送设置
        batch_size = self.batch_spin.value()
        delay = self.delay_spin.value()
        repeat_count = self.repeat_spin.value()
        concurrent_threads = self.concurrent_spin.value()
        
        # 检查是否选择了"全部邮箱"
        is_multi_sender = from_email.startswith("🔄 全部邮箱")
        
        if is_multi_sender:
            # 获取所有激活的邮箱
            active_mailboxes = []
            for mailbox in self.mailboxes:
                address = mailbox.get('email', '')
                status = mailbox.get('status', 'active')
                if address and status == 'active':
                    active_mailboxes.append(address)
            
            if not active_mailboxes:
                QMessageBox.warning(self, "错误", "没有可用的激活邮箱")
                return
            
            # 计算总发送数量
            total_sends = len(to_emails) * len(active_mailboxes)
            
            # 确认发送
            html_info = "是" if is_html else "否"
            reply = QMessageBox.question(self, "确认发送", 
                                       f"确定要使用全部邮箱并发发送邮件吗？\n\n"
                                       f"发件人邮箱: {len(active_mailboxes)} 个\n"
                                       f"收件人数量: {len(to_emails)} 个\n"
                                       f"总发送数量: {total_sends} 封\n"
                                       f"主题: {subject}\n"
                                       f"HTML格式: {html_info}\n"
                                       f"并发线程数: {concurrent_threads}\n"
                                       f"批次延时: {delay}秒",
                                       QMessageBox.Yes | QMessageBox.No)
            
            if reply != QMessageBox.Yes:
                return
            
            # 开始多发件人发送
            self.send_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setMaximum(total_sends)
            self.progress_bar.setValue(0)
            
            # 更新统计
            self.total_label.setText(f"总数: {total_sends}")
            self.success_label.setText("成功: 0")
            self.failed_label.setText("失败: 0")
            
            # 获取是否为HTML邮件
            is_html = self.html_checkbox.isChecked()
            
            # 创建多发件人并发发送线程
            self.send_thread = MultiSenderEmailThread(
                self.api, active_mailboxes, to_emails, subject, content, batch_size, delay, concurrent_threads, is_html
            )
            
        else:
            # 单发件人发送
            # 移除可能的"(禁用)"标记
            clean_from_email = from_email.replace(" (禁用)", "")
            
            # 计算总发送数量（包含重复发送）
            total_sends = len(to_emails) * repeat_count
            
            # 确认发送
            html_info = "是" if is_html else "否"
            reply = QMessageBox.question(self, "确认发送", 
                                       f"确定要并发发送邮件吗？\n\n"
                                       f"发件人: {clean_from_email}\n"
                                       f"收件人数量: {len(to_emails)}\n"
                                       f"重复发送次数: {repeat_count}\n"
                                       f"总发送数量: {total_sends} 封\n"
                                       f"主题: {subject}\n"
                                       f"HTML格式: {html_info}\n"
                                       f"并发线程数: {concurrent_threads}\n"
                                       f"批次延时: {delay}秒",
                                       QMessageBox.Yes | QMessageBox.No)
            
            if reply != QMessageBox.Yes:
                return
            
            # 开始单发件人发送
            self.send_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.progress_bar.setVisible(True)
            self.progress_bar.setMaximum(total_sends)
            self.progress_bar.setValue(0)
            
            # 更新统计
            self.total_label.setText(f"总数: {total_sends}")
            self.success_label.setText("成功: 0")
            self.failed_label.setText("失败: 0")
            
            # 获取是否为HTML邮件
            is_html = self.html_checkbox.isChecked()
            
            # 创建单发件人并发发送线程（包含重复发送参数）
            self.send_thread = ConcurrentEmailThread(
                self.api, clean_from_email, to_emails, subject, content, concurrent_threads, delay, repeat_count, is_html
            )
        
        # 连接信号并启动线程
        self.send_thread.progress_updated.connect(self.update_progress)
        self.send_thread.send_completed.connect(self.send_completed)
        self.send_thread.start()
    
    def stop_sending(self):
        """停止发送邮件"""
        if self.send_thread and self.send_thread.isRunning():
            self.send_thread.stop()
            self.send_thread.wait()
        
        self.send_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText("发送已停止")
    
    def update_progress(self, current, total, status):
        """更新发送进度"""
        self.progress_bar.setValue(current)
        self.status_label.setText(status)
    
    def send_completed(self, success_count, failed_count):
        """发送完成"""
        self.send_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        # 更新统计
        self.success_label.setText(f"成功: {success_count}")
        self.failed_label.setText(f"失败: {failed_count}")
        
        total_count = success_count + failed_count
        self.status_label.setText(f"发送完成！成功 {success_count}/{total_count}")
        
        # 添加到历史记录
        self.add_to_history(success_count, failed_count)
        
        # 显示结果
        QMessageBox.information(self, "发送完成", 
                              f"邮件发送完成！\n\n"
                              f"成功: {success_count}\n"
                              f"失败: {failed_count}\n"
                              f"总计: {total_count}")
    
    def add_to_history(self, success_count, failed_count):
        """添加到发送历史"""
        row_count = self.history_table.rowCount()
        self.history_table.insertRow(row_count)
        
        # 时间
        import datetime
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        self.history_table.setItem(row_count, 0, QTableWidgetItem(current_time))
        
        # 收件人数量
        total_count = success_count + failed_count
        self.history_table.setItem(row_count, 1, QTableWidgetItem(f"{total_count} 个"))
        
        # 主题
        subject = self.subject_edit.text()[:20] + "..." if len(self.subject_edit.text()) > 20 else self.subject_edit.text()
        self.history_table.setItem(row_count, 2, QTableWidgetItem(subject))
        
        # 状态
        status = f"成功 {success_count}/{total_count}"
        self.history_table.setItem(row_count, 3, QTableWidgetItem(status))
        
        # 滚动到最新记录
        self.history_table.scrollToBottom()
    
    def clear_data(self):
        """清空数据"""
        self.from_combo.clear()
        self.to_text.clear()
        self.subject_edit.clear()
        self.content_text.clear()
        self.html_checkbox.setChecked(False)
        self.history_table.setRowCount(0)
        self.progress_bar.setVisible(False)
        self.status_label.setText("就绪")
        self.total_label.setText("总数: 0")
        self.success_label.setText("成功: 0")
        self.failed_label.setText("失败: 0")
