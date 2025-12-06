#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打包脚本 - 将思凡邮箱群发工具打包成exe文件
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def install_pyinstaller():
    """安装PyInstaller"""
    print("正在安装PyInstaller...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("✅ PyInstaller安装成功!")
    except subprocess.CalledProcessError as e:
        print(f"❌ PyInstaller安装失败: {e}")
        return False
    return True

def create_spec_file():
    """创建PyInstaller配置文件"""
    spec_content = '''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('config.json', '.'),
        ('ui', 'ui'),
    ],
    hiddenimports=[
        'PyQt5.QtCore',
        'PyQt5.QtGui', 
        'PyQt5.QtWidgets',
        'requests',
        'json',
        'base64',
        'os',
        'sys',
        'time',
        'datetime',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyd = []
for d in a.datas:
    if 'pyconfig' in d[0]:
        pyd.append(d)

a.datas = [x for x in a.datas if x not in pyd]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='思凡邮箱群发工具',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version_file='version_info.txt'
)
'''
    
    with open('思凡邮箱群发工具.spec', 'w', encoding='utf-8') as f:
        f.write(spec_content)
    
    print("✅ 配置文件创建成功!")

def create_version_info():
    """创建版本信息文件"""
    version_content = '''# UTF-8
#
# For more details about fixed file info 'ffi' see:
# http://msdn.microsoft.com/en-us/library/ms646997.aspx
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1,0,0,0),
    prodvers=(1,0,0,0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'080404B0',
        [StringStruct(u'CompanyName', u'思凡开发团队'),
        StringStruct(u'FileDescription', u'思凡邮箱群发工具'),
        StringStruct(u'FileVersion', u'1.0.0'),
        StringStruct(u'InternalName', u'思凡邮箱群发工具'),
        StringStruct(u'LegalCopyright', u'Copyright © 2025 思凡开发团队'),
        StringStruct(u'OriginalFilename', u'思凡邮箱群发工具.exe'),
        StringStruct(u'ProductName', u'思凡邮箱群发工具'),
        StringStruct(u'ProductVersion', u'1.0.0')])
      ]), 
    VarFileInfo([VarStruct(u'Translation', [2052, 1200])])
  ]
)
'''
    
    with open('version_info.txt', 'w', encoding='utf-8') as f:
        f.write(version_content)
    
    print("✅ 版本信息文件创建成功!")

def build_exe():
    """构建exe文件"""
    print("正在构建exe文件...")
    try:
        # 使用PyInstaller构建
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--clean",
            "--noconfirm", 
            "思凡邮箱群发工具.spec"
        ]
        
        subprocess.check_call(cmd)
        print("✅ exe文件构建成功!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ 构建失败: {e}")
        return False

def copy_to_target():
    """复制到目标目录"""
    source_exe = Path("dist/思凡邮箱群发工具.exe")
    target_dir = Path("软件")
    
    # 创建目标目录
    target_dir.mkdir(exist_ok=True)
    
    if source_exe.exists():
        target_exe = target_dir / "思凡邮箱群发工具.exe"
        shutil.copy2(source_exe, target_exe)
        print(f"✅ exe文件已复制到: {target_exe.absolute()}")
        
        # 复制配置文件
        config_files = ["config.json", "README.md", "使用说明.md"]
        for config_file in config_files:
            if Path(config_file).exists():
                shutil.copy2(config_file, target_dir / config_file)
                print(f"✅ 已复制: {config_file}")
        
        return True
    else:
        print("❌ 找不到构建的exe文件")
        return False

def cleanup():
    """清理临时文件"""
    print("正在清理临时文件...")
    
    cleanup_items = [
        "build",
        "dist", 
        "__pycache__",
        "思凡邮箱群发工具.spec",
        "version_info.txt"
    ]
    
    for item in cleanup_items:
        item_path = Path(item)
        if item_path.exists():
            if item_path.is_dir():
                shutil.rmtree(item_path)
            else:
                item_path.unlink()
            print(f"✅ 已清理: {item}")

def main():
    """主函数"""
    print("=" * 50)
    print("思凡邮箱群发工具 - 打包脚本")
    print("=" * 50)
    
    # 检查当前目录
    if not Path("main.py").exists():
        print("❌ 错误：请在项目根目录运行此脚本")
        return
    
    # 步骤1：安装PyInstaller
    if not install_pyinstaller():
        return
    
    # 步骤2：创建配置文件
    create_spec_file()
    create_version_info()
    
    # 步骤3：构建exe
    if not build_exe():
        return
    
    # 步骤4：复制到目标目录
    if not copy_to_target():
        return
    
    # 步骤5：清理临时文件
    cleanup()
    
    print("\n" + "=" * 50)
    print("🎉 打包完成!")
    print("📁 exe文件位置: 软件/思凡邮箱群发工具.exe")
    print("=" * 50)

if __name__ == "__main__":
    main()