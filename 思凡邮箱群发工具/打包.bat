@echo off
chcp 65001
echo ========================================
echo 思凡邮箱群发工具 - 打包脚本
echo ========================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误：未找到Python，请先安装Python
    pause
    exit /b 1
)

REM 安装PyInstaller
echo 正在安装PyInstaller...
pip install pyinstaller
if errorlevel 1 (
    echo 错误：PyInstaller安装失败
    pause
    exit /b 1
)

REM 创建软件目录
if not exist "软件" mkdir "软件"

REM 打包exe文件
echo.
echo 正在打包exe文件...
pyinstaller --onefile --windowed --name "思凡邮箱群发工具" --distpath "软件" main.py

if errorlevel 1 (
    echo 错误：打包失败
    pause
    exit /b 1
)

REM 复制配置文件到软件目录
echo.
echo 正在复制配置文件...
copy "config.json" "软件\" >nul 2>&1
copy "README.md" "软件\" >nul 2>&1
copy "使用说明.md" "软件\" >nul 2>&1

REM 清理临时文件
echo.
echo 正在清理临时文件...
if exist "build" rmdir /s /q "build"
if exist "思凡邮箱群发工具.spec" del "思凡邮箱群发工具.spec"

echo.
echo ========================================
echo 🎉 打包完成！
echo 📁 exe文件位置: 软件\思凡邮箱群发工具.exe
echo ========================================
pause