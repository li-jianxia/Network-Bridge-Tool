# Network Bridge Tool

A PyQt5-based GUI application for bridging UDP and TCP network connections with real-time monitoring and management capabilities.

## Features

- **Bidirectional UDP-TCP Bridge**
- Real-time connection monitoring
- Automatic port allocation
- Multi-client TCP server management
- Connection heartbeat detection
- Detailed logging system
- Configuration persistence
- Network interface selection
- Connection statistics visualization

## Requirements

- Python 3.6+
- PyQt5
- System network configuration access

## Installation

```bash
pip install pyqt5
```

## Usage

1. **Run the application**:
```bash
python "Network Bridge Tool.py"
```

2. **Interface Overview**:
- Select network interface from dropdown
- Configure UDP port (default: 8888)
- Manage device IP list
- View real-time port mapping table

3. **Configuration**:
- Click "Unlock" (default password: `admin`)
- Add/remove device IPs
- Adjust UDP port
- Click "Save Config" to persist settings

4. **Monitoring**:
- View live connection statistics
- Hover over connection counts for client details
- Use "Save Log" to export session logs

## Configuration File (`config.json`)

```json
{
  "udp_port": 8888,
  "device_ips": ["192.168.1.100", "192.168.1.101"],
  "ip_port_map": {
    "192.168.1.100": 5000,
    "192.168.1.101": 5001
  }
}
```

## UDP Device Port

- udp port：8889

## Logging

- Log file: `network_bridge.log`
- Real-time log viewer in UI
- Log levels: DEBUG, INFO, WARNING, ERROR
- Timestamp format: `YYYY-MM-DD HH:MM:SS.sss`

---

**Note**: Requires administrator privileges for port access below 1024.

# 网络桥接工具

一个基于 PyQt5 的 GUI 应用程序，用于桥接 UDP 和 TCP 网络连接，并具有实时监控和管理功能。

## 功能

- 双向 UDP-TCP 桥梁
- 实时连接监控
- 自动端口分配
- 多客户端 TCP 服务器管理
- 连接心跳检测
- 详细的日志系统
- 配置持久化
- 网络接口选择
- 连接统计可视化

## 要求

- Python 3.6+
- PyQt5
系统网络配置访问

## 安装

```bash
pip install pyqt5
```

## 使用方法

运行应用程序：
```bash
python "Network Bridge Tool.py"
```

2. **界面概述**：
- 从下拉菜单中选择网络接口
- 配置 UDP 端口（默认：8888）
- 管理设备 IP 列表
- 查看实时端口映射表

3. **配置**:
- 点击“解锁”（默认密码：`admin`）
- 添加/删除设备 IP 地址
- 调整 UDP 端口
- 点击"保存配置"以保存设置

4. **监控**:
查看实时连接统计
移动光标至连接计数上以查看客户端详情
使用“保存日志”导出会话日志

## 配置文件（config.json）

```json
{
"udp_port": 8888,
"device_ips": ["192.168.1.100", "192.168.1.101"],
"ip_port_map": {
"192.168.1.100": 5000,
"192.168.1.101": 5001
}
}
```

## UDP设备端口

- udp端口号：8889

## 日志记录

- 日志文件: `network_bridge.log`
- UI 中的实时日志查看器
- 日志级别: DEBUG, INFO, WARNING, ERROR
时间戳格式: `YYYY-MM-DD HH:MM:SS.sss`

---

**注意**：需要管理员权限以访问 1024 以下的端口。
