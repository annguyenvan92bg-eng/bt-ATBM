# Thông tin sinh viên
- Tên : Nguyễn Văn An
- Lớp : K59KTP.K01
- MSSV: K235480106002
# Bài tập môn An toàn và Bảo mật thông tin
## Bài 1 :Mã hóa AES
- Tạo app dùng console
1. Môi trường

Python 3.8 trở lên

Thư viện cryptography

Hệ điều hành: Windows / Linux / macOS

2. Cài đặt và chạy

bash

pip install cryptography

cd <thư mục chứa aes_app.py>

python aes_app.py

3. Chức năng chương trình

1	Sinh khoá AES	Chọn 128, 192 hoặc 256 bit, khoá sinh ngẫu nhiên bằng os.urandom

2	Lưu khoá ra file	Ghi khoá thô (raw bytes) vào file, mặc định aes.key

3	Import khoá từ file	Đọc khoá, kiểm tra độ dài hợp lệ (16/24/32 bytes)

4	Mã hoá văn bản	Nhập chuỗi, in bản mã dạng base64 và giải mã lại để kiểm tra

5	Giải mã văn bản	Nhập bản mã base64, in ra bản rõ

6	Mã hoá file	nguồn, lưu vào file đầu ra (mặc định thêm đuôi .enc)

7	Giải mã file .enc, lưu vào file đầu ra (mặc định thêm đuôi .dec)

8	Thử nghiệm file lớn	Đo thời gian, so sánh byte

4. Thiết kế kỹ thuật

Thuật toán: AES ở chế độ CBC, padding PKCS7.

IV: sinh ngẫu nhiên cho mỗi lần mã hoá, ghi ở 16 byte đầu của dữ liệu mã hoá. Vì vậy cùng một văn bản mã hoá nhiều lần sẽ cho bản mã khác nhau.

Xử lý file lớn: đọc và mã hoá theo từng khối 4 MB (streaming), nên bộ nhớ sử dụng gần như không đổi dù file nặng hàng GB.

So sánh bytes: đọc song song hai file theo từng khối và so sánh, nếu khác sẽ báo vị trí byte khác đầu tiên.

Đo thời gian: dùng time.perf_counter().

Cấu trúc file mã hoá

| IV (16 bytes)  | Ciphertext (AES-CBC + PKCS7 padding)  |

Kích thước file mã hoá = kích thước file gốc + 16 byte IV + 1 đến 16 byte padding.
