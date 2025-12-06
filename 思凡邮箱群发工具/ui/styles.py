# -*- coding: utf-8 -*-
"""
UI样式表
现代化蓝色主题风格
"""

# 主题色彩定义
COLORS = {
    'primary': '#4A90E2',      # 主蓝色
    'primary_dark': '#357ABD', # 深蓝色
    'primary_light': '#6BA3E8', # 浅蓝色
    'secondary': '#F5F7FA',    # 浅灰背景
    'success': '#5CB85C',      # 成功绿色
    'danger': '#D9534F',       # 危险红色
    'warning': '#F0AD4E',      # 警告橙色
    'info': '#5BC0DE',         # 信息蓝色
    'light': '#FFFFFF',        # 白色
    'dark': '#333333',         # 深色文字
    'border': '#E1E8ED',       # 边框色
    'hover': '#E8F4FD',        # 悬停色
}

# 现代化蓝色主题样式
MODERN_BLUE_STYLE = f"""
/* 全局样式 */
QWidget {{
    font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif;
    font-size: 9pt;
    color: {COLORS['dark']};
    background-color: {COLORS['light']};
}}

/* 主窗口 */
QMainWindow {{
    background-color: {COLORS['secondary']};
}}

/* 选项卡样式 */
QTabWidget::pane {{
    border: 1px solid {COLORS['border']};
    background-color: {COLORS['light']};
    border-radius: 6px;
}}

QTabWidget::tab-bar {{
    alignment: left;
}}

QTabBar::tab {{
    background-color: {COLORS['secondary']};
    color: {COLORS['dark']};
    padding: 10px 20px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    border: 1px solid {COLORS['border']};
    border-bottom: none;
    min-width: 80px;
}}

QTabBar::tab:selected {{
    background-color: {COLORS['primary']};
    color: {COLORS['light']};
    font-weight: bold;
}}

QTabBar::tab:hover:!selected {{
    background-color: {COLORS['hover']};
    color: {COLORS['primary']};
}}

/* 按钮样式 */
QPushButton {{
    background-color: {COLORS['primary']};
    color: {COLORS['light']};
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: bold;
    min-width: 80px;
}}

QPushButton:hover {{
    background-color: {COLORS['primary_dark']};
}}

QPushButton:pressed {{
    background-color: {COLORS['primary_dark']};
    padding-top: 9px;
    padding-bottom: 7px;
}}

QPushButton:disabled {{
    background-color: #CCCCCC;
    color: #666666;
}}

/* 成功按钮 */
QPushButton[class="success"] {{
    background-color: {COLORS['success']};
}}

QPushButton[class="success"]:hover {{
    background-color: #4CAE4C;
}}

/* 危险按钮 */
QPushButton[class="danger"] {{
    background-color: {COLORS['danger']};
}}

QPushButton[class="danger"]:hover {{
    background-color: #C9302C;
}}

/* 输入框样式 */
QLineEdit, QTextEdit, QPlainTextEdit {{
    border: 2px solid {COLORS['border']};
    border-radius: 4px;
    padding: 8px;
    background-color: {COLORS['light']};
    selection-background-color: {COLORS['primary_light']};
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {COLORS['primary']};
    outline: none;
}}

/* 下拉框样式 */
QComboBox {{
    border: 2px solid {COLORS['border']};
    border-radius: 4px;
    padding: 8px;
    background-color: {COLORS['light']};
    min-width: 120px;
}}

QComboBox:focus {{
    border-color: {COLORS['primary']};
}}

QComboBox::drop-down {{
    border: none;
    width: 20px;
}}

QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid {COLORS['dark']};
    margin-right: 5px;
}}

QComboBox QAbstractItemView {{
    border: 1px solid {COLORS['border']};
    background-color: {COLORS['light']};
    selection-background-color: {COLORS['hover']};
    selection-color: {COLORS['primary']};
}}

/* 数字输入框样式 */
QSpinBox {{
    border: 2px solid {COLORS['border']};
    border-radius: 4px;
    padding: 8px;
    background-color: {COLORS['light']};
}}

QSpinBox:focus {{
    border-color: {COLORS['primary']};
}}

/* 复选框样式 */
QCheckBox {{
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 2px solid {COLORS['border']};
    border-radius: 3px;
    background-color: {COLORS['light']};
}}

QCheckBox::indicator:checked {{
    background-color: {COLORS['primary']};
    border-color: {COLORS['primary']};
}}

QCheckBox::indicator:checked::after {{
    content: "✓";
    color: {COLORS['light']};
    font-weight: bold;
}}

/* 分组框样式 */
QGroupBox {{
    font-weight: bold;
    border: 2px solid {COLORS['border']};
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 10px;
    background-color: {COLORS['light']};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 8px 0 8px;
    color: {COLORS['primary']};
    background-color: {COLORS['light']};
}}

/* 表格样式 */
QTableWidget {{
    gridline-color: {COLORS['border']};
    background-color: {COLORS['light']};
    alternate-background-color: {COLORS['secondary']};
    selection-background-color: {COLORS['hover']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
}}

QTableWidget::item {{
    padding: 8px;
    border-bottom: 1px solid {COLORS['border']};
}}

QTableWidget::item:selected {{
    background-color: {COLORS['primary_light']};
    color: {COLORS['light']};
}}

QHeaderView::section {{
    background-color: {COLORS['primary']};
    color: {COLORS['light']};
    padding: 10px;
    border: none;
    font-weight: bold;
}}

QHeaderView::section:first {{
    border-top-left-radius: 4px;
}}

QHeaderView::section:last {{
    border-top-right-radius: 4px;
}}

/* 进度条样式 */
QProgressBar {{
    border: 2px solid {COLORS['border']};
    border-radius: 4px;
    text-align: center;
    background-color: {COLORS['secondary']};
}}

QProgressBar::chunk {{
    background-color: {COLORS['primary']};
    border-radius: 2px;
}}

/* 标签样式 */
QLabel {{
    color: {COLORS['dark']};
}}

QLabel[class="title"] {{
    font-size: 14pt;
    font-weight: bold;
    color: {COLORS['primary']};
}}

QLabel[class="success"] {{
    color: {COLORS['success']};
    font-weight: bold;
}}

QLabel[class="danger"] {{
    color: {COLORS['danger']};
    font-weight: bold;
}}

QLabel[class="warning"] {{
    color: {COLORS['warning']};
    font-weight: bold;
}}

/* 滚动条样式 */
QScrollBar:vertical {{
    background-color: {COLORS['secondary']};
    width: 12px;
    border-radius: 6px;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS['primary']};
    border-radius: 6px;
    min-height: 20px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLORS['primary_dark']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    border: none;
    background: none;
}}

/* 分割器样式 */
QSplitter::handle {{
    background-color: {COLORS['border']};
}}

QSplitter::handle:horizontal {{
    width: 2px;
}}

QSplitter::handle:vertical {{
    height: 2px;
}}

/* 状态栏样式 */
QStatusBar {{
    background-color: {COLORS['secondary']};
    border-top: 1px solid {COLORS['border']};
    color: {COLORS['dark']};
}}

/* 菜单栏样式 */
QMenuBar {{
    background-color: {COLORS['light']};
    border-bottom: 1px solid {COLORS['border']};
}}

QMenuBar::item {{
    padding: 8px 12px;
    background-color: transparent;
}}

QMenuBar::item:selected {{
    background-color: {COLORS['hover']};
    color: {COLORS['primary']};
}}

QMenu {{
    background-color: {COLORS['light']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
}}

QMenu::item {{
    padding: 8px 20px;
}}

QMenu::item:selected {{
    background-color: {COLORS['hover']};
    color: {COLORS['primary']};
}}

/* 对话框样式 */
QDialog {{
    background-color: {COLORS['light']};
}}

/* 工具提示样式 */
QToolTip {{
    background-color: {COLORS['dark']};
    color: {COLORS['light']};
    border: 1px solid {COLORS['border']};
    border-radius: 4px;
    padding: 4px;
}}
"""

def apply_style(app):
    """应用样式到应用程序"""
    app.setStyleSheet(MODERN_BLUE_STYLE)