import sys
import time
import json
import socket
import logging
import threading
from datetime import datetime

from PyQt5.QtGui import QColor, QCursor, QIcon, QPainter, QPixmap
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, pyqtSignal, QEvent, QTimer
from PyQt5.QtNetwork import QHostAddress, QNetworkInterface, QAbstractSocket

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('network_bridge.log'),
        logging.StreamHandler()
    ]
)

class LogHandler(logging.Handler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def emit(self, record):
        msg = self.format(record)
        self.callback(msg)


class EnhancedNetworkManager:
    def __init__(self, config, log_callback, update_callback):
        self.config = config
        self.log_callback = log_callback
        self.udp_socket = None
        self.tcp_servers = {}
        self.running = False
        self.base_port = 5000  # 起始端口号

        self.update_callback = update_callback  # 新增状态更新回调
        self.traffic_timer = QTimer()
        self.traffic_timer.timeout.connect(self.update_stats)
        # 初始化统计定时器
        self.traffic_timer = threading.Timer(1.0, self.update_stats)
        self.traffic_timer.daemon = True
        self.traffic_timer.start()

    def update_stats(self):
        """统计信息收集方法"""
        stats = {
            'details': []
        }
        for port, server in self.tcp_servers.items():
            stats['details'].append({
                "port": port,
                "connections": server.connection_count
            })
        # 通过回调传递数据到UI
        self.update_callback(stats)
        # 循环触发定时器
        self.traffic_timer = threading.Timer(1.0, self.update_stats)
        self.traffic_timer.start()

    def initialize_ports(self):
        """自动分配TCP端口"""
        self.config['ip_port_map'] = {}
        for idx, ip in enumerate(self.config['device_ips']):
            self.config['ip_port_map'][ip] = self.base_port + idx

    def start_services(self):
        self.running = True
        self.start_udp_server()
        self.start_tcp_servers()

    def log(self, message, level='info'):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_msg = f"[{timestamp}] [{level.upper()}] {message}"
        self.log_callback(log_msg)

    def start_udp_server(self):
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind(('0.0.0.0', self.config['udp_port']))
            threading.Thread(target=self.udp_listener, daemon=True).start()
            self.log(f"UDP server started on port {self.config['udp_port']}")
        except Exception as e:
            self.log(f"UDP server error: {str(e)}", 'error')

    def udp_listener(self):
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(1024)
                if addr[0] in self.config['device_ips']:
                    port = self.config['ip_port_map'].get(addr[0])
                    if port in self.tcp_servers:
                        # 添加异常处理
                        try:
                            self.tcp_servers[port].broadcast(data)
                        except Exception as e:
                            self.log(f"UDP转发TCP失败: {str(e)}", 'error')
            except Exception as e:
                if self.running:
                    self.log(f"UDP receive error: {str(e)}", 'error')
                break

    def start_tcp_servers(self):
        for ip, port in self.config['ip_port_map'].items():
            try:
                # 创建TCPServer时传入UDP目标IP和套接字
                server = TCPServer(
                    port=port,
                    udp_target_ip=ip,
                    udp_socket=self.udp_socket,
                    log_callback=self.log_callback
                )
                server.start()
                self.tcp_servers[port] = server
                self.log(f"TCP server started on port {port}")
            except Exception as e:
                self.log(f"TCP server error on port {port}: {str(e)}", 'error')

    def stop_all(self):
        self.running = False
        if self.udp_socket:
            self.udp_socket.close()
        for server in self.tcp_servers.values():
            server.stop()


class TCPServer:
    def __init__(self, port, udp_target_ip, udp_socket, log_callback):
        self.connection_count = 0
        self.port = port
        self.udp_port = 8889
        self.udp_target_ip = udp_target_ip  # 新增：对应的UDP设备IP
        self.udp_socket = udp_socket        # 新增：UDP套接字引用
        self.log_callback = log_callback
        self.clients = []
        self.client_lock = threading.Lock()  # 新增客户端列表锁
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))
        self.sock.listen(5)
        self.thread = threading.Thread(target=self.listen, daemon=True)
        threading.Thread(target=self.heartbeat_check, daemon=True).start()

    def start(self):
        self.thread.start()

    def listen(self):
        self.sock.settimeout(1)  # 设置超时以检测退出
        while self.running:
            try:
                client, addr = self.sock.accept()
                self.clients.append(client)
                threading.Thread(target=self.handle_client, args=(client,)).start()
            except socket.timeout:
                continue  # 正常检测运行状态
            except Exception as e:
                if self.running:
                    self.log(f"TCP client error: {str(e)}", 'error')
                break

    def handle_client(self, client):
        client_ip = client.getpeername()[0]
        self.connection_count += 1
        try:
            while self.running:
                try:
                    data = client.recv(1024)
                    if not data:  # 检测到客户端主动断开
                        raise ConnectionResetError("Client closed connection")
                    if data:
                        # Forward to UDP
                        # 新增：转发到UDP设备
                        self.udp_socket.sendto(data, (self.udp_target_ip, self.udp_port))
                        # self.log(f"转发TCP数据到UDP {self.udp_target_ip}:{self.udp_port}", 'info')
                        pass  # Implement UDP forwarding
                except Exception as e:
                    self.log(f"Client handling error: {str(e)}", 'error')
                    break
        except Exception as e:
            self.log(f"客户端 {client_ip} 异常: {str(e)}", 'error')
        finally:
            self.connection_count -= 1
            with self.client_lock:  # 线程安全操作
                if client in self.clients:
                    self.clients.remove(client)
                    client.close()
                    self.log(f"已清理客户端 {client_ip} 的连接", 'debug')

    # 添加心跳机制（在TCPServer类中）
    def heartbeat_check(self):
        while self.running:
            time.sleep(30)  # 每30秒检测一次
            dead_clients = []
            with self.client_lock:
                current_clients = self.clients.copy()

            for client in current_clients:
                try:
                    # 发送空包检测连接状态
                    client.sendall(b'\x00')
                except Exception as e:
                    dead_clients.append(client)
                    self.log(f"客户端 {client} 异常: {str(e)}", 'error')

            # 清理失效客户端...
            if dead_clients:
                with self.client_lock:
                    for dc in dead_clients:
                        if dc in self.clients:
                            self.clients.remove(dc)
                            dc.close()
                            self.log(f"清理失效客户端连接", 'info')

    def broadcast(self, data):
        dead_clients = []
        with self.client_lock:  # 线程安全读取
            current_clients = self.clients.copy()
        for client in current_clients:
            try:
                client.sendall(data)
            except (ConnectionResetError, BrokenPipeError) as e:
                self.log(f"发送失败（客户端已断开）: {str(e)}", 'warning')
                dead_clients.append(client)
            except Exception as e:
                self.log(f"Broadcast error: {str(e)}", 'error')
                dead_clients.append(client)

        # 清理失效客户端
        if dead_clients:
            with self.client_lock:
                for dc in dead_clients:
                    if dc in self.clients:
                        self.clients.remove(dc)
                        dc.close()
                        self.log(f"清理失效客户端连接", 'info')

    def stop(self):
        self.running = False
        self.sock.close()

    def log(self, message, level='info'):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_msg = f"[{timestamp}] [{level.upper()}] {message}"
        self.log_callback(log_msg)


class ConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Unlock Configuration")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        QBtn = QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        self.buttonBox = QDialogButtonBox(QBtn)
        self.buttonBox.accepted.connect(self.verify)
        self.buttonBox.rejected.connect(self.reject)
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Enter admin password:"))
        layout.addWidget(self.password)
        layout.addWidget(self.buttonBox)
        self.setLayout(layout)

    def verify(self):
        if self.password.text() == "admin":
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Invalid password!")


class MainWindow(QMainWindow):
    update_log = pyqtSignal(str)
    update_ports = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.default_config = {
            'udp_port': 8888,
            'device_ips': [],
            'ip_port_map': {}
        }
        self.locked = True
        self.network_manager = None
        self.selected_interface_ip = "0.0.0.0"  # 新增当前选择接口IP缓存
        self.current_config = self.default_config.copy()
        self.init_ui()
        self.load_config()
        self.set_editable(False)
        self.init_network()

        self.interface_combo.currentIndexChanged.connect(self.update_interface_ip)  # 绑定接口变更事件

    def init_ui(self):
        self.setWindowTitle("Network Bridge Tool")
        main_widget = QWidget()
        layout = QVBoxLayout()

        # Configuration Section
        config_group = QGroupBox("Configuration")
        form_layout = QFormLayout()

        self.interface_combo = QComboBox()
        self.populate_interfaces()
        form_layout.addRow("Network Interface:", self.interface_combo)

        self.udp_port = QSpinBox()
        self.udp_port.setRange(1, 65535)
        form_layout.addRow("UDP Port:", self.udp_port)

        self.device_list = QListWidget()
        self.add_device_btn = QPushButton("+")
        self.add_device_btn.clicked.connect(self.add_device_ip)
        device_layout = QHBoxLayout()
        device_layout.addWidget(self.device_list)
        device_layout.addWidget(self.add_device_btn)
        form_layout.addRow("Device IPs:", device_layout)

        # 新增端口映射显示表格
        self.port_table = QTableWidget()
        self.port_table.setColumnCount(4)
        self.port_table.setHorizontalHeaderLabels([
            'Device IP',
            'TCP Server IP',
            'TCP Port',
            'Connections'
        ])
        # 在配置组中添加表格
        form_layout.addRow("Port Mapping:", self.port_table)

        # 添加日志保存按钮
        self.log_save_btn = QPushButton("Save Log")
        self.log_save_btn.clicked.connect(self.save_log)

        # 启用单元格进入事件
        self.port_table.viewport().installEventFilter(self)

        config_group.setLayout(form_layout)

        # Control Section
        control_layout = QHBoxLayout()
        self.lock_btn = QPushButton("Unlock")
        self.lock_btn.clicked.connect(self.toggle_lock)
        self.save_btn = QPushButton("Save Config")
        self.save_btn.clicked.connect(self.save_config)
        control_layout.addWidget(self.lock_btn)
        control_layout.addWidget(self.save_btn)

        # Log Section
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)

        layout.addWidget(config_group)
        layout.addLayout(control_layout)
        layout.addWidget(QLabel("Logs:"))
        layout.addWidget(self.log_view)

        # 在布局中添加新组件
        layout.addWidget(self.log_save_btn)

        main_widget.setLayout(layout)
        self.setCentralWidget(main_widget)


    # 在MainWindow类中添加以下方法
    def update_ui_stats(self, stats):
        # 更新表格数据
        for row in range(self.port_table.rowCount()):
            port = int(self.port_table.item(row, 2).text())
            for detail in stats['details']:
                if detail['port'] == port:
                    # 更新连接状态
                    conn_item = QTableWidgetItem(str(detail['connections']))
                    conn_item.setIcon(self.get_status_icon(detail['connections']))
                    self.port_table.setItem(row, 3, conn_item)
                    self.port_table.viewport().update()  # 强制重绘表格区域

    def get_status_icon(self, count):
        # 生成状态图标
        pixmap = QPixmap(16, 16)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QColor("green" if count > 0 else "red"))
        painter.drawEllipse(0, 0, 15, 15)
        painter.end()
        return QIcon(pixmap)

    # 新增方法：获取指定接口的IPv4地址
    def get_interface_ip(self, interface_name):
        interfaces = QNetworkInterface.allInterfaces()
        for interface in interfaces:
            if interface.humanReadableName() == interface_name:
                for entry in interface.addressEntries():
                    if entry.ip().protocol() == QAbstractSocket.IPv4Protocol:
                        return entry.ip().toString()
        return "0.0.0.0"

    # 新增方法：处理接口变更事件
    def update_interface_ip(self):
        interface_name = self.interface_combo.currentText()
        self.selected_interface_ip = self.get_interface_ip(interface_name)
        self.update_port_table_ip()  # 立即更新表格显示
        self.log(f"切换网络接口到: {interface_name} ({self.selected_interface_ip})")

    # 新增方法：更新表格中的IP列
    def update_port_table_ip(self):
        for row in range(self.port_table.rowCount()):
            ip_item = QTableWidgetItem(self.selected_interface_ip)
            ip_item.setFlags(ip_item.flags() & ~Qt.ItemIsEditable)  # 设为不可编辑
            self.port_table.setItem(row, 1, ip_item)

    def save_log(self):
        # 日志保存功能
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Log", "", "Text Files (*.txt)")
        if filename:
            with open(filename, 'w') as f:
                f.write(self.log_view.toPlainText())

    def log_message(self, message):
        # 自动滚动到底部
        self.log_view.append(message)
        self.log_view.ensureCursorVisible()

    def log(self, message, level='info'):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_msg = f"[{timestamp}] [{level.upper()}] {message}"
        self.log_message(log_msg)

    # 设备IP列表编辑功能改进
    def add_device_ip(self, item=None):
        ip, ok = QInputDialog.getText(
            self,
            "Edit Device IP" if item else "Add Device IP",
            "Enter IP address:",
            text=item.text() if item else ""
        )
        if ok and ip:
            if item:  # 编辑现有项
                item.setText(ip)
            else:  # 添加新项
                list_item = QListWidgetItem(ip)
                list_item.setFlags(list_item.flags() | Qt.ItemIsEditable)
                self.device_list.addItem(list_item)

    def eventFilter(self, source, event):
        # 实现鼠标悬停提示
        if event.type() == QEvent.ToolTip and source is self.port_table.viewport():
            index = self.port_table.indexAt(event.pos())
            if index.column() == 3:  # 连接数列
                return self.show_connection_tooltip(index)
        return super().eventFilter(source, event)

    def closeEvent(self, event):
        """重写窗口关闭事件"""
        # 停止所有网络服务
        if self.network_manager:
            self.network_manager.stop_all()

        # 等待线程结束（可选）
        # self.wait_for_threads()

        # 确认退出
        event.accept()

    def wait_for_threads(self, timeout=3):
        """等待网络线程结束"""
        start = time.time()
        while self.network_manager.running:
            if time.time() - start > timeout:
                self.log("强制终止线程超时！", 'warning')
                break
            time.sleep(0.1)

    def show_connection_tooltip(self, index):
        # 获取连接信息
        ip_item = self.port_table.item(index.row(), 0)
        server = self.network_manager.tcp_servers.get(
            int(self.port_table.item(index.row(), 2).text())
        )
        if server:
            clients = [f"{c.getpeername()[0]}:{c.getpeername()[1]}"
                      for c in server.clients]
            QToolTip.showText(
                QCursor.pos(),
                f"Connected Clients:\n" + "\n".join(clients),
                self.port_table
            )
            return True
        return False

    def populate_interfaces(self):
        interfaces = QNetworkInterface.allInterfaces()
        for interface in interfaces:
            if interface.flags() & QNetworkInterface.IsUp:
                self.interface_combo.addItem(interface.humanReadableName())

    def toggle_lock(self):
        if self.locked:
            dlg = ConfigDialog(self)
            if dlg.exec_():
                self.locked = False
                self.lock_btn.setText("Lock")
                self.set_editable(True)
                self.statusBar().showMessage("配置已解锁", 3000)
        else:
            self.locked = True
            self.lock_btn.setText("Unlock")
            self.set_editable(False)
            self.statusBar().showMessage("配置已锁定", 3000)

    def set_editable(self, editable):
        self.interface_combo.setEnabled(editable)
        self.udp_port.setReadOnly(not editable)
        self.add_device_btn.setEnabled(editable)
        self.device_list.setEnabled(editable)

        # 设置控件样式强化状态显示
        style = "" if editable else "background: #f0f0f0;"
        self.udp_port.setStyleSheet(f"QSpinBox {{ {style} }}")
        self.device_list.setStyleSheet(f"QListWidget {{ {style} }}")


    def load_config(self):
        try:
            with open("config.json", "r") as f:
                saved_config = json.load(f)
                # 配置项合并与验证
                self.current_config.update({
                    'udp_port': saved_config.get('udp_port', 8888),
                    'device_ips': saved_config.get('device_ips', []),
                    'ip_port_map': saved_config.get('ip_port_map', {})
                })
            # 更新UI组件
            self.udp_port.setValue(self.current_config['udp_port'])
            self.device_list.clear()
            for ip in self.current_config['device_ips']:
                list_item = QListWidgetItem(ip)
                list_item.setFlags(list_item.flags() | Qt.ItemIsEditable)
                self.device_list.addItem(list_item)
            self.update_interface_ip()
            self.update_port_table()
        except Exception as e:
            logging.error(f"加载配置失败: {str(e)}")

    def save_config(self):
        """改进的配置保存方法"""
        try:
            # 独立构造配置对象，不再依赖network_manager
            new_config = {
                'udp_port': self.udp_port.value(),
                'device_ips': [self.device_list.item(i).text()
                               for i in range(self.device_list.count())],
                'ip_port_map': self.current_config['ip_port_map'].copy()
            }

            # 合并端口映射数据
            if hasattr(self, 'network_manager') and self.network_manager:
                new_config['ip_port_map'].update(
                    self.network_manager.config.get('ip_port_map', {})
                )

            with open("config.json", "w") as f:
                json.dump(new_config, f)

            self.current_config = new_config
            self.update_port_table()
            QMessageBox.information(self, "成功", "配置已保存")
            self.restart_services()
        except Exception as e:
            logging.error(f"保存配置失败: {str(e)}")
            QMessageBox.critical(self, "错误", f"保存失败: {str(e)}")

    def update_port_table(self):
        """更新端口映射表格"""
        self.port_table.setRowCount(0)
        for row, (ip, port) in enumerate(self.current_config['ip_port_map'].items()):
            self.port_table.insertRow(row)
            ip_item = QTableWidgetItem(ip)
            ip_item.setFlags(ip_item.flags() & ~Qt.ItemIsEditable)  # 设为不可编辑
            self.port_table.setItem(row, 0, ip_item)
            ip_item = QTableWidgetItem(self.selected_interface_ip)
            ip_item.setFlags(ip_item.flags() & ~Qt.ItemIsEditable)  # 设为不可编辑
            self.port_table.setItem(row, 1, ip_item)
            self.port_table.setItem(row, 2, QTableWidgetItem(str(port)))

    def restart_services(self):
        """重启网络服务"""
        if self.network_manager:
            self.network_manager.stop_all()
        self.network_manager = EnhancedNetworkManager(
            self.current_config,
            self.log_message,
            self.update_ui_stats  # 新增回调绑定
        )
        self.network_manager.initialize_ports()
        self.network_manager.start_services()
        self.update_port_table()

    def init_network(self):
        """安全的网络初始化"""
        try:
            self.network_manager = EnhancedNetworkManager(
                self.current_config,
                self.log_message,
                self.update_ui_stats  # 新增回调绑定
            )
            self.network_manager.initialize_ports()
            self.network_manager.start_services()
            # 初始化端口映射
            self.current_config['ip_port_map'] = self.network_manager.config['ip_port_map']
            self.update_port_table()
        except Exception as e:
            logging.error(f"网络初始化失败: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
