#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
思凡邮箱群发工具
基于miko邮箱域名API开发的邮件群发工具
"""

import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from ui.main_window import MainWindow
from ui.styles import apply_style

def main():
    """主函数"""
    app = QApplication(sys.argv)
    app.setApplicationName("思凡邮箱群发工具")
    app.setApplicationVersion("1.0.0")
    
    # 应用现代化蓝色主题样式
    apply_style(app)
    
    # 设置应用图标
    if os.path.exists("resources/icon.ico"):
        app.setWindowIcon(QIcon("resources/icon.ico"))
    
    # 创建主窗口
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()