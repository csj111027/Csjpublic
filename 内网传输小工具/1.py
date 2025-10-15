import os
import time
import socket
import threading
from flask import Flask, request, redirect, url_for, send_from_directory, render_template_string, send_file
from werkzeug.utils import secure_filename
import mimetypes
import platform
import json
from datetime import datetime
import uuid

# 创建Flask应用
app = Flask(__name__)

# 配置上传文件夹
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 * 10  # 10GB文件大小限制

# 确保上传文件夹存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 聊天消息存储
CHAT_HISTORY_FILE = 'chat_history.json'
chat_history = []

# 加载聊天历史
def load_chat_history():
    global chat_history
    try:
        if os.path.exists(CHAT_HISTORY_FILE):
            with open(CHAT_HISTORY_FILE, 'r', encoding='utf-8') as f:
                chat_history = json.load(f)
    except:
        chat_history = []

# 保存聊天历史
def save_chat_history():
    try:
        with open(CHAT_HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(chat_history, f, ensure_ascii=False, indent=2)
    except:
        pass

# 初始化聊天历史
load_chat_history()

def get_local_ip():
    """获取本机内网IP地址"""
    try:
        # 创建一个临时socket连接来获取本机IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # 连接Google的DNS服务器
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        try:
            # 备选方法：通过主机名获取IP
            host_name = socket.gethostname()
            return socket.gethostbyname(host_name)
        except:
            return "127.0.0.1"  # 默认回环地址

def format_size(size):
    """格式化文件大小为易读格式"""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size/1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size/(1024 * 1024):.1f} MB"
    else:
        return f"{size/(1024 * 1024 * 1024):.1f} GB"

def get_disk_usage(path):
    """获取磁盘使用情况"""
    try:
        if platform.system() == 'Windows':
            import ctypes
            free_bytes = ctypes.c_ulonglong(0)
            total_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p(path), None, ctypes.pointer(total_bytes), ctypes.pointer(free_bytes))
            total = total_bytes.value
            free = free_bytes.value
            used = total - free
            return total, used, free
        else:
            stat = os.statvfs(path)
            total = stat.f_frsize * stat.f_blocks
            free = stat.f_frsize * stat.f_bfree
            used = total - free
            return total, used, free
    except:
        return 0, 0, 0

def get_file_type(filename):
    """根据文件扩展名获取文件类型"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    file_types = {
        'txt': '文本文件',
        'pdf': 'PDF文档',
        'png': 'PNG图片',
        'jpg': 'JPG图片',
        'jpeg': 'JPEG图片',
        'gif': 'GIF图片',
        'bmp': 'BMP图片',
        'svg': 'SVG矢量图',
        'doc': 'Word文档',
        'docx': 'Word文档',
        'xls': 'Excel表格',
        'xlsx': 'Excel表格',
        'ppt': 'PPT演示文稿',
        'pptx': 'PPT演示文稿',
        'zip': '压缩文件',
        'rar': '压缩文件',
        '7z': '压缩文件',
        'tar': '压缩文件',
        'gz': '压缩文件',
        'mp3': '音频文件',
        'wav': '音频文件',
        'ogg': '音频文件',
        'flac': '音频文件',
        'mp4': 'MP4视频',
        'mov': 'MOV视频',
        'avi': 'AVI视频',
        'mkv': 'MKV视频',
        'webm': 'WebM视频',
        'flv': 'FLV视频',
        'wmv': 'WMV视频',
        'csv': 'CSV文件',
        'html': 'HTML文件',
        'css': 'CSS文件',
        'js': 'JavaScript文件',
        'json': 'JSON文件',
        'xml': 'XML文件',
        'py': 'Python脚本',
        'java': 'Java代码',
        'c': 'C代码',
        'cpp': 'C++代码'
    }
    return file_types.get(ext, '其他文件')

def is_previewable(filename):
    """检查文件是否支持预览"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    previewable_extensions = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'mp3', 'wav', 'ogg', 'flac',
        'mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv',
        'csv', 'html', 'css', 'js', 'json', 'xml', 'py', 'java', 'c', 'cpp'
    }
    return ext in previewable_extensions

def get_mime_type(filename):
    """获取文件的MIME类型"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    mime_types = {
        'txt': 'text/plain',
        'pdf': 'application/pdf',
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'bmp': 'image/bmp',
        'svg': 'image/svg+xml',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'mp3': 'audio/mpeg',
        'wav': 'audio/wav',
        'ogg': 'audio/ogg',
        'flac': 'audio/flac',
        'mp4': 'video/mp4',
        'mov': 'video/quicktime',
        'avi': 'video/x-msvideo',
        'mkv': 'video/x-matroska',
        'webm': 'video/webm',
        'flv': 'video/x-flv',
        'wmv': 'video/x-ms-wmv',
        'csv': 'text/csv',
        'html': 'text/html',
        'css': 'text/css',
        'js': 'application/javascript',
        'json': 'application/json',
        'xml': 'application/xml',
        'py': 'text/x-python',
        'java': 'text/x-java',
        'c': 'text/x-c',
        'cpp': 'text/x-c++'
    }
    return mime_types.get(ext, 'application/octet-stream')

# 主页面HTML模板
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>内网文件共享与聊天</title>
    <style>
        body { font-family: 'Microsoft YaHei', sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f8f9fa; }
        .container { background-color: white; padding: 25px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; }
        .section { margin-bottom: 30px; padding: 20px; background-color: #f8f9fa; border-radius: 8px; }
        .btn { background-color: #3498db; color: white; padding: 12px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; transition: all 0.3s; }
        .btn:hover { background-color: #2980b9; transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .btn-danger { background-color: #e74c3c; }
        .btn-danger:hover { background-color: #c0392b; }
        .file-list { list-style-type: none; padding: 0; }
        .file-item { background-color: white; padding: 15px; margin-bottom: 12px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; transition: all 0.3s; border-left: 4px solid #3498db; }
        .file-item:hover { transform: translateY(-3px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .file-info { flex-grow: 1; }
        .file-name { font-weight: bold; font-size: 17px; color: #2c3e50; }
        .file-meta { display: flex; gap: 15px; margin-top: 8px; font-size: 14px; color: #7f8c8d; }
        .file-actions { display: flex; gap: 12px; }
        .file-action-btn { padding: 10px 15px; border-radius: 6px; text-decoration: none; display: flex; align-items: center; gap: 8px; font-size: 14px; transition: all 0.2s; }
        .preview-btn { background-color: #3498db; color: white; }
        .preview-btn:hover { background-color: #2980b9; }
        .download-btn { background-color: #2ecc71; color: white; }
        .download-btn:hover { background-color: #27ae60; }
        .delete-btn { background-color: #e74c3c; color: white; }
        .delete-btn:hover { background-color: #c0392b; }
        .form-group { margin-bottom: 20px; }
        input[type="file"] { padding: 12px; width: 100%; border: 2px dashed #3498db; border-radius: 6px; background-color: #f8f9fa; }
        .message { padding: 15px; margin-bottom: 20px; border-radius: 6px; font-size: 16px; }
        .success { background-color: #d4edda; color: #155724; border-left: 5px solid #28a745; }
        .error { background-color: #f8d7da; color: #721c24; border-left: 5px solid #dc3545; }
        .info { background-color: #d1ecf1; color: #0c5460; border-left: 5px solid #17a2b8; }
        .qr-code { text-align: center; margin: 20px 0; }
        .qr-code img { max-width: 200px; }
        .usage { background-color: #e8f5e9; padding: 15px; border-radius: 8px; margin-bottom: 25px; }
        .file-type { font-size: 0.9em; color: #666; }
        .system-info { display: flex; flex-wrap: wrap; gap: 20px; margin-top: 20px; }
        .info-card { background-color: #fff; padding: 15px; border-radius: 8px; flex: 1; min-width: 250px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .info-card h3 { margin-top: 0; }
        .preview-container { margin-top: 20px; padding: 15px; background-color: #fff; border-radius: 8px; }
        .preview-content { max-height: 500px; overflow: auto; }
        .text-preview { white-space: pre-wrap; font-family: monospace; }
        .image-preview { max-width: 100%; max-height: 400px; }
        .back-btn { margin-top: 15px; }
        .time-display { font-size: 1.2em; font-weight: bold; text-align: center; margin: 10px 0; }
        
        /* 聊天界面样式 */
        .chat-container { background-color: white; border-radius: 8px; padding: 15px; margin-top: 20px; }
        .chat-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .chat-messages { height: 300px; overflow-y: auto; padding: 10px; background-color: #f8f9fa; border-radius: 6px; margin-bottom: 15px; }
        .message-item { margin-bottom: 10px; padding: 10px; border-radius: 6px; background-color: #e3f2fd; }
        .message-item.self { background-color: #d1ecf1; text-align: right; }
        .message-sender { font-weight: bold; color: #3498db; }
        .message-time { font-size: 0.8em; color: #7f8c8d; }
        .chat-input-container { display: flex; gap: 10px; }
        .chat-input { flex-grow: 1; padding: 10px; border: 1px solid #ddd; border-radius: 6px; }
        .chat-send-btn { padding: 10px 20px; background-color: #3498db; color: white; border: none; border-radius: 6px; cursor: pointer; }
        .chat-send-btn:hover { background-color: #2980b9; }
    </style>
    <script>
        function updateTime() {
            const now = new Date();
            const timeString = now.getFullYear() + '-' + 
                              String(now.getMonth() + 1).padStart(2, '0') + '-' + 
                              String(now.getDate()).padStart(2, '0') + ' ' + 
                              String(now.getHours()).padStart(2, '0') + ':' + 
                              String(now.getMinutes()).padStart(2, '0') + ':' + 
                              String(now.getSeconds()).padStart(2, '0');
            document.getElementById('current-time').textContent = timeString;
            
            // 每秒更新一次
            setTimeout(updateTime, 1000);
        }
        
        // 页面加载完成后开始更新时间
        document.addEventListener('DOMContentLoaded', function() {
            updateTime();
            
            // 初始化聊天功能
            initChat();
        });
        
        // 文件拖放功能
        document.addEventListener('DOMContentLoaded', function() {
            const dropArea = document.querySelector('.upload-section');
            const fileInput = document.querySelector('input[type="file"]');
            
            dropArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropArea.style.backgroundColor = '#e3f2fd';
            });
            
            dropArea.addEventListener('dragleave', () => {
                dropArea.style.backgroundColor = '';
            });
            
            dropArea.addEventListener('drop', (e) => {
                e.preventDefault();
                dropArea.style.backgroundColor = '';
                
                if (e.dataTransfer.files.length) {
                    fileInput.files = e.dataTransfer.files;
                    // 自动提交表单
                    document.querySelector('form').submit();
                }
            });
        });
        
        // 聊天功能
        let username = "用户" + Math.floor(Math.random() * 1000);
        let lastMessageId = 0;
        
        function initChat() {
            // 设置用户名
            const storedUsername = localStorage.getItem('chat_username');
            if (storedUsername) {
                username = storedUsername;
            } else {
                localStorage.setItem('chat_username', username);
            }
            document.getElementById('username').value = username;
            
            // 加载聊天历史
            loadChatHistory();
            
            // 开始轮询新消息
            setInterval(loadNewMessages, 2000);
        }
        
        function loadChatHistory() {
            fetch('/chat_history')
                .then(response => response.json())
                .then(data => {
                    displayMessages(data);
                    lastMessageId = data.length > 0 ? data[data.length - 1].id : 0;
                });
        }
        
        function loadNewMessages() {
            fetch(`/new_messages?last_id=${lastMessageId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.length > 0) {
                        displayMessages(data);
                        lastMessageId = data[data.length - 1].id;
                        // 滚动到底部
                        const chatMessages = document.getElementById('chat-messages');
                        chatMessages.scrollTop = chatMessages.scrollHeight;
                    }
                });
        }
        
        function displayMessages(messages) {
            const chatMessages = document.getElementById('chat-messages');
            chatMessages.innerHTML = '';
            
            messages.forEach(msg => {
                const isSelf = msg.sender === username;
                const messageElement = document.createElement('div');
                messageElement.className = `message-item ${isSelf ? 'self' : ''}`;
                
                messageElement.innerHTML = `
                    <div class="message-sender">${msg.sender}</div>
                    <div class="message-content">${msg.message}</div>
                    <div class="message-time">${msg.time}</div>
                `;
                
                chatMessages.appendChild(messageElement);
            });
            
            // 滚动到底部
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }
        
        function sendMessage() {
            const messageInput = document.getElementById('message-input');
            const message = messageInput.value.trim();
            
            if (message) {
                fetch('/send_message', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        sender: username,
                        message: message
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        messageInput.value = '';
                        // 加载新消息
                        loadNewMessages();
                    }
                });
            }
        }
        
        function updateUsername() {
            const newUsername = document.getElementById('username').value.trim();
            if (newUsername) {
                username = newUsername;
                localStorage.setItem('chat_username', username);
                alert('用户名已更新为: ' + username);
            }
        }
        
        // 处理Enter键发送消息
        document.getElementById('message-input').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    </script>
</head>
<body>
    <div class="container">
        <h1>内网文件共享与聊天系统</h1>
        
        <!-- 实时时间显示 -->
        <div class="time-display" id="current-time">{{ current_time }}</div>
        
        <!-- 使用说明 -->
        <div class="usage">
            <h3>使用说明：</h3>
            <p>1. 在同一局域网内的设备上，在浏览器中输入以下地址访问：</p>
            <p><strong>http://{{ host_ip }}:{{ port }}</strong></p>
            <p>2. 支持的文件类型：<strong>所有类型</strong>（包括但不限于文档、图片、视频、音频等）</p>
            <p>3. 支持预览的文件类型：MP4, MP3, MKV, PPT, Word, Excel, PDF, 图片等常见格式</p>
        </div>
        
        <!-- 文件上传区域 -->
        <div class="upload-section">
            <div class="section-title">
                <h2>上传文件</h2>
            </div>
            <form method="post" action="/upload" enctype="multipart/form-data">
                <div class="form-group">
                    <input type="file" name="file" required>
                </div>
                <button type="submit" class="btn">上传文件</button>
            </form>
        </div>
        
        <!-- 消息显示区域 -->
        {% if message %}
        <div class="message {{ message.category }}">{{ message.content }}</div>
        {% endif %}
        
        <!-- 文件列表区域 -->
        <div class="section">
            <div class="section-title">
                <h2>文件列表 <span class="file-count-badge">{{ file_count }} 个文件</span></h2>
            </div>
            {% if files %}
            <ul class="file-list">
                {% for file in files %}
                <li class="file-item">
                    <div class="file-info">
                        <div class="file-name">{{ file.name }}</div>
                        <div class="file-meta">
                            <span>{{ file.type }}</span>
                            <span>{{ file.size }}</span>
                            <span>{{ file.date }}</span>
                        </div>
                    </div>
                    <div class="file-actions">
                        {% if file.previewable %}
                        <a href="/preview/{{ file.name }}" class="file-action-btn preview-btn" title="预览">
                            <span>预览</span>
                        </a>
                        {% endif %}
                        <a href="/download/{{ file.name }}" class="file-action-btn download-btn" title="下载">
                            <span>下载</span>
                        </a>
                        <a href="/delete/{{ file.name }}" class="file-action-btn delete-btn" title="删除" onclick="return confirm('确定要删除 {{ file.name }} 吗？')">
                            <span>删除</span>
                        </a>
                    </div>
                </li>
                {% endfor %}
            </ul>
            {% else %}
            <div class="empty-state">
                <div>📁</div>
                <h3>没有文件</h3>
                <p>上传文件后，它们将显示在这里</p>
            </div>
            {% endif %}
        </div>
        
        <!-- 聊天功能 -->
        <div class="section">
            <div class="section-title">
                <h2>实时聊天</h2>
            </div>
            <div class="chat-container">
                <div class="chat-header">
                    <div>
                        <label for="username">用户名:</label>
                        <input type="text" id="username" style="padding: 5px; border: 1px solid #ddd; border-radius: 4px;">
                        <button onclick="updateUsername()" style="padding: 5px 10px; background-color: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer;">更新</button>
                    </div>
                    <div>当前用户: <span id="current-user" style="font-weight: bold;">{{ username }}</span></div>
                </div>
                <div id="chat-messages" class="chat-messages">
                    <!-- 聊天消息将在这里显示 -->
                </div>
                <div class="chat-input-container">
                    <input type="text" id="message-input" class="chat-input" placeholder="输入消息...">
                    <button onclick="sendMessage()" class="chat-send-btn">发送</button>
                </div>
            </div>
        </div>
        
        <!-- 系统信息 -->
        <div class="section">
            <div class="section-title">
                <h2>系统信息</h2>
            </div>
            <div class="system-info">
                <div class="info-card">
                    <h3>服务器信息</h3>
                    <p>IP地址: {{ host_ip }}</p>
                    <p>端口: {{ port }}</p>
                    <p>存储路径: {{ upload_folder }}</p>
                </div>
                <div class="info-card">
                    <h3>存储状态</h3>
                    <p>磁盘空间: {{ disk_space }}</p>
                    <p>文件数量: {{ file_count }}</p>
                    <p>总文件大小: {{ total_size }}</p>
                </div>
                <div class="info-card">
                    <h3>服务状态</h3>
                    <p>运行时间: {{ uptime }}</p>
                    <p>系统平台: {{ platform }}</p>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

# 文件预览HTML模板
PREVIEW_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>预览文件 - {{ filename }}</title>
    <style>
        body { font-family: 'Microsoft YaHei', sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background-color: #f8f9fa; }
        .container { background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; margin-bottom: 20px; }
        .file-info { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #eee; }
        .file-name { font-size: 24px; font-weight: bold; color: #2c3e50; }
        .file-meta { display: flex; justify-content: center; gap: 20px; margin-top: 10px; color: #7f8c8d; }
        .preview-container { background-color: #f8f9fa; padding: 25px; border-radius: 10px; margin-bottom: 25px; }
        .preview-content { max-height: 70vh; overflow: auto; }
        .text-preview { white-space: pre-wrap; font-family: monospace; background-color: white; padding: 20px; border-radius: 8px; }
        .image-preview { max-width: 100%; max-height: 70vh; display: block; margin: 0 auto; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        .video-player { width: 100%; max-height: 70vh; border-radius: 8px; background-color: #000; }
        .audio-player { width: 100%; margin: 20px 0; }
        .back-btn { display: inline-block; margin: 20px 0; padding: 12px 25px; background-color: #3498db; color: white; text-decoration: none; text-align: center; border-radius: 6px; font-size: 16px; transition: all 0.3s; }
        .back-btn:hover { background-color: #2980b9; transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .unsupported { text-align: center; padding: 50px; background-color: white; border-radius: 8px; }
        .office-preview { width: 100%; height: 70vh; border: none; border-radius: 8px; }
        .action-buttons { display: flex; gap: 15px; justify-content: center; margin-top: 20px; }
        .action-btn { padding: 12px 25px; border-radius: 6px; text-decoration: none; font-size: 16px; }
        .download-btn { background-color: #2ecc71; color: white; }
        .download-btn:hover { background-color: #27ae60; }
    </style>
</head>
<body>
    <div class="container">
        <h1>文件预览</h1>
        
        <div class="file-info">
            <div class="file-name">{{ filename }}</div>
            <div class="file-meta">
                <span>类型: {{ file_type }}</span>
                <span>大小: {{ file_size }}</span>
                <span>上传时间: {{ file_date }}</span>
            </div>
        </div>
        
        <div class="preview-container">
            {% if preview_type == 'text' %}
                <div class="preview-content">
                    <pre class="text-preview">{{ file_content }}</pre>
                </div>
            {% elif preview_type == 'image' %}
                <div class="preview-content">
                    <img src="/download/{{ filename }}" alt="{{ filename }}" class="image-preview">
                </div>
            {% elif preview_type == 'video' %}
                <div class="preview-content">
                    <video controls class="video-player">
                        <source src="/download/{{ filename }}" type="{{ mime_type }}">
                        您的浏览器不支持视频播放
                    </video>
                </div>
            {% elif preview_type == 'audio' %}
                <div class="preview-content">
                    <audio controls class="audio-player">
                        <source src="/download/{{ filename }}" type="{{ mime_type }}">
                        您的浏览器不支持音频播放
                    </audio>
                </div>
            {% elif preview_type == 'pdf' %}
                <div class="preview-content">
                    <iframe src="/download/{{ filename }}" width="100%" height="600px" style="border: none;"></iframe>
                </div>
            {% elif preview_type == 'office' %}
                <div class="preview-content">
                    <!-- 使用Microsoft Office Online预览 -->
                    <iframe class="office-preview" src="https://view.officeapps.live.com/op/embed.aspx?src={{ file_url }}"></iframe>
                </div>
            {% else %}
                <div class="unsupported">
                    <h3>不支持在线预览</h3>
                    <p>此文件类型不支持在线预览，请下载后查看</p>
                </div>
            {% endif %}
        </div>
        
        <div class="action-buttons">
            <a href="/" class="action-btn back-btn">返回文件列表</a>
            <a href="/download/{{ filename }}" class="action-btn download-btn">下载文件</a>
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    """显示主页面"""
    # 获取文件列表
    files = []
    total_size_bytes = 0
    
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(filepath):
            size = os.path.getsize(filepath)
            total_size_bytes += size
            mtime = os.path.getmtime(filepath)
            date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
            files.append({
                'name': filename, 
                'size': format_size(size),
                'date': date_str,
                'type': get_file_type(filename),
                'previewable': is_previewable(filename)
            })
    
    # 按修改时间排序（最新在前）
    files.sort(key=lambda x: os.path.getmtime(os.path.join(app.config['UPLOAD_FOLDER'], x['name'])), reverse=True)
    
    # 获取当前时间（初始值）
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    
    # 获取磁盘空间信息
    total, used, free = get_disk_usage(app.config['UPLOAD_FOLDER'])
    
    # 获取系统信息
    platform_info = platform.platform()
    
    # 渲染页面
    return render_template_string(HTML_TEMPLATE, 
                                 files=files,
                                 file_count=len(files),
                                 host_ip=HOST_IP,
                                 port=PORT,
                                 current_time=current_time,
                                 upload_folder=os.path.abspath(app.config['UPLOAD_FOLDER']),
                                 disk_space=f"已用: {format_size(used)} / 总共: {format_size(total)}",
                                 total_size=format_size(total_size_bytes),
                                 platform=platform_info,
                                 uptime=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                                 message=request.args.get('message'))

@app.route('/upload', methods=['POST'])
def upload_file():
    """处理文件上传"""
    # 检查是否有文件被上传
    if 'file' not in request.files:
        return redirect(url_for('index', message={'content': '没有选择文件', 'category': 'error'}))
    
    file = request.files['file']
    
    # 检查文件名是否为空
    if file.filename == '':
        return redirect(url_for('index', message={'content': '没有选择文件', 'category': 'error'}))
    
    # 保存文件
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return redirect(url_for('index', message={'content': f'文件 {filename} 上传成功', 'category': 'success'}))

@app.route('/download/<filename>')
def download_file(filename):
    """提供文件下载"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        return redirect(url_for('index', message={'content': f'文件 {filename} 不存在', 'category': 'error'}))
    
    # 设置正确的MIME类型
    mime_type = get_mime_type(filename)
    return send_file(filepath, as_attachment=True, mimetype=mime_type)

@app.route('/preview/<filename>')
def preview_file(filename):
    """预览文件内容"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return redirect(url_for('index', message={'content': f'文件 {filename} 不存在', 'category': 'error'}))
    
    # 获取文件信息
    size = os.path.getsize(filepath)
    mtime = os.path.getmtime(filepath)
    date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
    file_type = get_file_type(filename)
    mime_type = get_mime_type(filename)
    
    # 根据文件类型确定预览方式
    preview_type = 'other'
    file_content = ""
    file_url = f"http://{HOST_IP}:{PORT}/download/{filename}"
    
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    # 文本文件预览
    if ext in ['txt', 'csv', 'html', 'css', 'js', 'json', 'xml', 'py', 'java', 'c', 'cpp']:
        preview_type = 'text'
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                file_content = f.read()
        except:
            try:
                with open(filepath, 'r', encoding='gbk') as f:
                    file_content = f.read()
            except:
                file_content = "无法解码文件内容"
    
    # 图片文件预览
    elif ext in ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg']:
        preview_type = 'image'
    
    # 视频文件预览
    elif ext in ['mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv']:
        preview_type = 'video'
    
    # 音频文件预览
    elif ext in ['mp3', 'wav', 'ogg', 'flac']:
        preview_type = 'audio'
    
    # PDF文件预览
    elif ext == 'pdf':
        preview_type = 'pdf'
    
    # Office文件预览
    elif ext in ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']:
        preview_type = 'office'
    
    return render_template_string(PREVIEW_TEMPLATE,
                                 filename=filename,
                                 file_type=file_type,
                                 file_size=format_size(size),
                                 file_date=date_str,
                                 preview_type=preview_type,
                                 file_content=file_content,
                                 mime_type=mime_type,
                                 file_url=file_url)

@app.route('/delete/<filename>')
def delete_file(filename):
    """删除文件"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
            return redirect(url_for('index', message={'content': f'文件 {filename} 已删除', 'category': 'success'}))
        except Exception as e:
            return redirect(url_for('index', message={'content': f'删除文件失败: {str(e)}', 'category': 'error'}))
    else:
        return redirect(url_for('index', message={'content': f'文件 {filename} 不存在', 'category': 'error'}))

# 聊天功能路由
@app.route('/chat_history')
def get_chat_history():
    """获取完整的聊天历史"""
    return json.dumps(chat_history)

@app.route('/new_messages')
def get_new_messages():
    """获取新的聊天消息"""
    last_id = int(request.args.get('last_id', 0))
    new_messages = [msg for msg in chat_history if msg['id'] > last_id]
    return json.dumps(new_messages)

@app.route('/send_message', methods=['POST'])
def send_message():
    """发送聊天消息"""
    data = request.get_json()
    if data and 'sender' in data and 'message' in data:
        new_message = {
            'id': len(chat_history) + 1,
            'sender': data['sender'],
            'message': data['message'],
            'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        chat_history.append(new_message)
        
        # 保存聊天历史
        save_chat_history()
        
        return json.dumps({'status': 'success', 'message_id': new_message['id']})
    return json.dumps({'status': 'error', 'message': 'Invalid data'}), 400

if __name__ == '__main__':
    # 配置端口
    PORT = 5000
    
    # 获取本机内网IP
    HOST_IP = get_local_ip()
    
    # 启动Flask应用
    print(f"服务启动中，请访问 http://{HOST_IP}:{PORT}")
    print(f"上传文件夹: {os.path.abspath(UPLOAD_FOLDER)}")
    print("按 Ctrl+C 停止服务")
    
    app.run(host='0.0.0.0', port=PORT, debug=False)