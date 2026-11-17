# CrowdSec Manager - Web Dashboard & Console

Trang web quản trị CrowdSec đa năng với giao diện trực quan, hiện đại, hỗ trợ Dark/Light Mode và Menu 3 gạch điều hướng giữa các phân hệ:
1. **Tab 1: Quyết định chặn (Decisions)**: Quản lý danh sách IP đang bị cấm (Bans).
2. **Tab 2: Quản lý Scenarios (Kịch bản)**: Xem, thêm, sửa, bật/tắt và xóa kịch bản phát hiện trong `/etc/crowdsec/scenarios/`.
3. **Tab 3: Theo dõi tình trạng hệ thống**: Xem tình trạng CPU, RAM và các card mạng

---

## Tính năng chính

### 🍔 1. Menu 3 gạch điều hướng (Sidebar Drawer)
- Nút menu 3 gạch ở góc trái trên cùng màn hình.
- Mở bảng điều hướng trượt mượt mà (Drawer) để chuyển đổi giữa các tab:
  - 🛡️ **Danh Sách Chặn (Decisions)** (Hiển thị số lượng IP đang bị chặn).
  - 📜 **Quản Lý Scenarios** (Hiển thị số lượng kịch bản đang bật).
- Ghi nhớ tab đang mở vào `localStorage`.

### 🛡️ 2. Tab 1 - Quản lý IP bị chặn (Decisions)
- **Hiển thị danh sách IP bị chặn**: Tương đương lệnh `cscli decisions list`, đầy đủ 10 cột dữ liệu chuẩn terminal.
- **Xóa IP chặn (Unban)**: Tương đương `cscli decisions delete -i <IP>` (hoặc `-r <Range>`, `--id <ID>`) với hộp thoại xác nhận an toàn.
- **Thêm IP chặn thủ công**: Tương đương `cscli decisions add -i <IP>`, hỗ trợ chọn thời hạn nhanh (`1h`, `4h`, `24h`, `7d`, `30d`), xem trước lệnh CLI thời gian thực.
- **Tìm kiếm & Tự động làm mới**: Live search theo IP, lý do, quốc gia; tự làm mới sau 5s, 10s, 30s.

### 📜 3. Tab 2 - Quản lý Kịch bản phát hiện (Scenarios)
- **Hiển thị danh sách Scenarios**:
  - Tương đương lệnh `cscli scenarios list` kết hợp quét thư mục `/etc/crowdsec/scenarios/`.
  - Hiển thị tên scenario, loại (Local Tùy chỉnh hay Hub), trạng thái (Enabled/Disabled), mô tả và đường dẫn file thực tế trên đĩa.
  - Hỗ trợ lọc theo trạng thái (Bật/Tắt) hoặc loại (Tùy chỉnh/Hub) và cờ `-a`.
- **Thêm Scenario mới**:
  - Nhập tên file (tự động lưu vào `/etc/crowdsec/scenarios/<tên_file>.yml`).
  - Khung soạn thảo YAML Editor tiện lợi kèm các mẫu chuẩn thông dụng:
    - *Leaky Bucket* (DDoS Flood, Brute Force như Suricata).
    - *Trigger* (Chặn tức thì khi gặp request độc hại).
    - *Counter* (Giới hạn tần suất request).
  - Tự động nạp lại CrowdSec (`systemctl reload crowdsec`).
- **Bật / Tắt Scenarios**:
  - Nút bấm trực tiếp trên từng dòng kịch bản.
  - Với kịch bản Hub: Tương đương `cscli scenarios install` / `cscli scenarios remove`.
  - Với kịch bản Local: Tự động đổi tên file kích hoạt hoặc vô hiệu hóa (`.disabled`).
- **Chỉnh sửa Scenarios (Edit & Save)**:
  - Bấm vào nút "Sửa" hoặc tên scenario để mở khung soạn thảo YAML.
  - Đọc trực tiếp nội dung file, cho phép chỉnh sửa cấu hình (filters, capacity, leakspeed...).
  - Tự động tạo bản sao lưu an toàn (`.bak`) trước khi ghi đè.
- **Xóa Scenarios**:
  - Hộp thoại xác nhận trước khi xóa.
  - Xóa file trên đĩa hoặc gọi `cscli scenarios remove <name> --purge`.

### 🌓 4. Chế độ Giao diện (Dark / Light Mode)
- Nút chuyển nhanh Mặt trời ☀️ / Mặt trăng 🌙 trên thanh điều hướng.
- Tự động phát hiện theme của hệ điều hành và lưu lựa chọn của bạn.

### ⚡ 5. Zero-Dependency (Không cài thêm thư viện)
- Viết bằng 100% Python 3 Standard Library + Vanilla HTML/CSS/JS.
- Không cần cài `pip`, `flask`, `node.js`.

---

## Hướng dẫn sử dụng

### 1. Khởi chạy bằng script
```bash
cd /home/viettung/crowdsec-dashboard
sudo ./start.sh
# Hoặc chỉ định cổng khác:
sudo ./start.sh 8000
```

### 2. Khởi chạy bằng lệnh Python trực tiếp
```bash
sudo python3 /home/viettung/crowdsec-dashboard/app.py --port 5000
```

### 3. Dùng thử chế độ Demo
```bash
python3 /home/viettung/crowdsec-dashboard/app.py --demo --port 5000
```

---

## Truy cập Web
- Máy cục bộ: `http://localhost:5000`
- Trong mạng LAN: `http://192.168.38.20:5000` hoặc `http://172.10.10.20:5000`

---

## Cài đặt chạy ngầm tự động (Systemd Service)
```bash
sudo cp /home/viettung/crowdsec-dashboard/crowdsec-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now crowdsec-dashboard
```
