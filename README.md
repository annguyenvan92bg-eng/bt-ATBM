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

5. Test các chức năng trên máy thật
- Sinh khóa AES
  <img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/00edd94c-ab09-4553-9120-41f82ff43919" />
  *Ảnh này cho thấy chương trình đã tự động sinh khóa AES-256 thành công
- Lưu khóa ra file
  <img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/4e1a56cf-e39d-4138-ab25-265c5e0711fa" />
  *Ảnh này đã lưu khóa vừa tạo thành công vào file mặc định có tên aes.key
- Import khóa từ file
 <img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/c5992985-33cf-43fc-a320-83f66915d784" />
* Ảnh này cho thấy đã import khóa thành công từ file aes.key
  
- Mã hóa đoạn văn bản(in kết quả mã hóa ra màn hình)
  
  <img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/0a405505-3773-40e0-a092-3560c6f7cbcd" />
  
  *Ảnh này cho thấy đã mã hóa đoạn văn bản thành công từ khóa vừa tạo
  <img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/6f75c669-e085-46d8-a64f-a9a970d2197a" />
 *Ảnh này đã giải mã đoạn văn bản thành công từ mã base64
- Mã hóa 1 file (lưu vào 1 file)
  
  <img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/99c89cae-48d2-43c5-b7a2-e2098b0b32ae" />

  *Ảnh này cho thấy file nguồn đã được mã hóa thành công và lưu vào file có đuôi .enc

  <img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/14d4c806-edc9-49d1-97a6-d30026d9b4cb" />

  *Ảnh này đã giải mã file mã hóa .enc thành công rồi lưu lại với đuôi .dec

- Thử nghiệm file có GB lớn
  <img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/7e681a56-4b7d-464d-ac62-ef074aa5c69c" />
* Ảnh này cho thấy chương trình đã mã hóa và giải mã thành công 1 file test 1GB do chương trình tự tạo 

  Với cấu hình máy :<img width="643" height="124" alt="image" src="https://github.com/user-attachments/assets/5e90a5d6-b604-4197-9911-7506ccf4c858" />

  Đã mã hóa và giải mã file 1GB với thời gian lần lượt là 2.328 s  (439.9 MB/s)-1.913 s  (535.2 MB/s)

  File mã hoá lớn hơn nguồn 32 bytes (16 byte IV + padding).

  File giải mã trùng khớp từng byte với file gốc => mã hoá/giải mã đúng.

- Kết luận 

Thời gian mã hoá và giải mã tăng gần tuyến tính theo kích thước file.

Thời gian mã hoá và giải mã xấp xỉ nhau vì AES là thuật toán đối xứng, hai chiều có chi phí tương đương.

Tốc độ phụ thuộc vào CPU (có hỗ trợ AES-NI hay không) và tốc độ ổ đĩa.

File giải mã trùng khớp từng byte với file gốc, chứng tỏ quá trình mã hoá và giải mã đúng.

File mã hoá lớn hơn file gốc một lượng rất nhỏ (IV và padding), không đáng kể so với kích thước file.

Cần giữ bí mật khoá: mất khoá hoặc dùng sai khoá thì không thể giải mã.

Note : Có thể tải file code bài 1 về test trên máy để xem thực tế các file key mã hóa trong tài liệu đều là dữ liệu test nên không sợ lộ
  

