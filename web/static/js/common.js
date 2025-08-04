// Miko邮箱系统通用JavaScript函数

// 全局配置
window.MikoEmail = {
    apiBase: '/api',
    version: '1.0.0'
};

// 通用工具函数
const Utils = {
    // 显示提示消息
    showAlert: function(message, type = 'info', duration = 5000) {
        // 移除现有的alert
        const existingAlert = document.querySelector('.alert.auto-dismiss');
        if (existingAlert) {
            existingAlert.remove();
        }
        
        // 创建新的alert
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show auto-dismiss`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // 插入到页面顶部
        const container = document.querySelector('.container, .container-fluid');
        if (container) {
            container.insertBefore(alertDiv, container.firstChild);
        } else {
            document.body.insertBefore(alertDiv, document.body.firstChild);
        }
        
        // 自动消失
        if (duration > 0) {
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.remove();
                }
            }, duration);
        }
    },

    // 显示加载状态
    showLoading: function(element, text = '加载中...') {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        
        if (element) {
            element.innerHTML = `
                <div class="d-flex align-items-center justify-content-center">
                    <div class="spinner-border spinner-border-sm me-2" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    ${text}
                </div>
            `;
            element.disabled = true;
        }
    },

    // 隐藏加载状态
    hideLoading: function(element, originalText = '') {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        
        if (element) {
            element.innerHTML = originalText;
            element.disabled = false;
        }
    },

    // 格式化日期
    formatDate: function(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diff = now - date;
        
        // 小于1分钟
        if (diff < 60000) {
            return '刚刚';
        }
        
        // 小于1小时
        if (diff < 3600000) {
            return Math.floor(diff / 60000) + '分钟前';
        }
        
        // 小于1天
        if (diff < 86400000) {
            return Math.floor(diff / 3600000) + '小时前';
        }
        
        // 小于7天
        if (diff < 604800000) {
            return Math.floor(diff / 86400000) + '天前';
        }
        
        // 超过7天显示具体日期
        return date.toLocaleDateString('zh-CN');
    },

    // 格式化文件大小
    formatFileSize: function(bytes) {
        if (bytes === 0) return '0 B';
        
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // 验证邮箱格式
    validateEmail: function(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    },

    // 验证邮箱前缀
    validateEmailPrefix: function(prefix) {
        const re = /^[a-zA-Z0-9._-]+$/;
        return re.test(prefix) && prefix.length > 0 && prefix.length <= 64;
    },

    // 复制到剪贴板
    copyToClipboard: function(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                this.showAlert('已复制到剪贴板', 'success', 2000);
            }).catch(() => {
                this.fallbackCopyToClipboard(text);
            });
        } else {
            this.fallbackCopyToClipboard(text);
        }
    },

    // 备用复制方法
    fallbackCopyToClipboard: function(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            this.showAlert('已复制到剪贴板', 'success', 2000);
        } catch (err) {
            this.showAlert('复制失败，请手动复制', 'warning');
        }
        
        document.body.removeChild(textArea);
    },

    // 确认对话框
    confirm: function(message, callback) {
        if (window.confirm(message)) {
            callback();
        }
    },

    // 防抖函数
    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // 节流函数
    throttle: function(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
};

// API请求封装
const API = {
    // 基础请求方法
    request: async function(method, url, data = null, options = {}) {
        const config = {
            method: method.toUpperCase(),
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        if (data && (method.toUpperCase() === 'POST' || method.toUpperCase() === 'PUT')) {
            config.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(window.MikoEmail.apiBase + url, config);
            const result = await response.json();
            
            if (!response.ok) {
                throw new Error(result.message || '请求失败');
            }
            
            return result;
        } catch (error) {
            console.error('API请求错误:', error);
            throw error;
        }
    },

    // GET请求
    get: function(url, options = {}) {
        return this.request('GET', url, null, options);
    },

    // POST请求
    post: function(url, data, options = {}) {
        return this.request('POST', url, data, options);
    },

    // PUT请求
    put: function(url, data, options = {}) {
        return this.request('PUT', url, data, options);
    },

    // DELETE请求
    delete: function(url, options = {}) {
        return this.request('DELETE', url, null, options);
    }
};

// 页面加载完成后的初始化
document.addEventListener('DOMContentLoaded', function() {
    // 初始化工具提示
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // 初始化弹出框
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // 自动关闭alert
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert.auto-dismiss');
        alerts.forEach(alert => {
            if (alert.parentNode) {
                alert.remove();
            }
        });
    }, 5000);
});

// 导出到全局
window.Utils = Utils;
window.API = API;
