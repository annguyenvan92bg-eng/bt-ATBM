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

* Note : Có thể tải file code bài 1 về test trên máy để xem thực tế các file key mã hóa trong tài liệu đều là dữ liệu test nên không sợ lộ
# Bài tập 2 : Mã hóa RSA  
- Ứng dụng .NET WinForms
## Chạy trong VS Code
1. Cài **.NET SDK** (https://dotnet.microsoft.com/download) và extension **C# Dev Kit** cho VS Code.
2. Kiểm tra phiên bản: `dotnet --version`.
  Mở `RsaApp.csproj` và đổi `netXX.0-windows` cho khớp.
3. Mở thư mục `RsaApp`  rồi chạy trong terminal:
   ```
   dotnet run
   ```
* Note :(Ứng dụng WinForms chỉ chạy trên Windows.)
## Các tab chức năng của chương trình
| Tab | Yêu cầu |
|-----|---------|
| 1-2. Sinh & xuất khoá | Sinh cặp khoá (1024/2048/3072/4096 bit), xuất `public.pem`, `private.pem` (X.509/PKCS#8 hoặc PKCS#1) |
| 3. Xem PEM | Phân tích PEM → DER: Tag, Length, Value của từng trường, ý nghĩa n, e, d, p, q, dP, dQ, qInv |
| 4. Import PEM | Nhập public key → n, e; nhập private key → n, e, d, p, q… |
| 5. Mã hoá | Dữ liệu ≤ 190 byte (khoá AES-256 = 32 byte, Base64) mã hoá bằng key đã import, kết quả Base64, lưu file |
| 6. Giải mã & so sánh | Đọc file Base64, giải mã bằng private key, so sánh với dữ liệu gốc |
| 7. Tốc độ | So sánh dùng public key (e nhỏ) và private key (d lớn), theo độ dài khoá |
| 8. SHA-256 | Băm 256 bit, đếm số bit khác nhau khi đổi đầu vào (hiệu ứng thác đổ) |
| 9. Chữ ký số | Ký bằng private key trên giá trị băm |

## Thiết kế
- Mã hoá: **RSA-OAEP với SHA-256**. Số byte tối đa = k − 2·32 − 2 = **190 byte** với khoá 2048 bit 
- PEM: public key dạng `PUBLIC KEY` (SubjectPublicKeyInfo) hoặc `RSA PUBLIC KEY` (PKCS#1); private key dạng `PRIVATE KEY` (PKCS#8) hoặc `RSA PRIVATE KEY` (PKCS#1).
- Chữ ký: SHA-256 + RSA (luỹ thừa bằng d trên giá trị băm đã đệm).

## Test thực tế các yêu cầu của bài toán
### Yêu cầu 1: Sinh cặp khoá (tab “1-2. Sinh & xuất khoá”)

Chọn 2048 bit rồi bấm “1. Sinh cặp khoá”.
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 180507" src="https://github.com/user-attachments/assets/599c1c68-349c-43db-b4ea-b3e81432b635" />
*Ảnh này đã sinh cặp khóa thành công 
### Yêu cầu 2: Xuất ra file PEM (cùng tab)

Bấm “2. Xuất ra file PEM…” và chọn một thư mục
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 180738" src="https://github.com/user-attachments/assets/ca4076a3-6633-4ef6-b078-f87c0752b1ae" />
*Ảnh này cho thấy xuất thành công cặp khóa ra 2 file pem public và private riêng biệt sau đó lưu lại vào thư mục đã chọn 
### Yêu cầu 3: View PEM (tab “3. Xem PEM”)

Bấm “Mở file PEM…”, chọn public.pem
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 181029" src="https://github.com/user-attachments/assets/14dfc05c-17ff-4b96-abbf-ac1553d9910d" />
*Ảnh này import pem public thành công từ file và cho thấy các ý nghĩa các byte trong format pem

Làm lại với private.pem
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 181155" src="https://github.com/user-attachments/assets/7ead15c9-d713-499b-b1c5-043333ae3b5e" />
*Ảnh này import pem private thành công từ file và cho thấy các ý nghĩa các byte trong format pem
### Yêu cầu 4: Nhập file PEM (tab “4. Import PEM”)

Bấm 4a, chọn public.pem
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 181244" src="https://github.com/user-attachments/assets/7dcaf9e2-14e3-4696-8db3-a2f225e6da46" />
*Ảnh này import và cho thấy thông số n,e của public key
Bấm 4b, chọn private.pem 
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 181259" src="https://github.com/user-attachments/assets/55d50455-34da-4db3-8665-00ea465a217e" />
*Ảnh này import và cho thấy thông số n và e, d, ... của private key
### Yêu cầu 5: Mã hoá (tab “5. Mã hoá”)

Bấm “Sinh khoá AES-256 (32 byte)”, ô dưới sẽ hiện chuỗi base64 và độ dài 32 byte.
Bấm “5. Mã hoá bằng public key” . Dòng thông tin sẽ cho thấy 32 byte vào, 256 byte ra, giới hạn 190 byte.
Bấm “Lưu kết quả ra file…”, đặt tên encrypted.txt, và chụp file đã lưu.
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 181518" src="https://github.com/user-attachments/assets/e37b3653-1632-4154-abe1-6dd9f4df094a" />
*Ảnh này đã sinh khóa AES-256 và mã hóa bằng public key đã import từ trước và cho ra kết quả phù hợp

### Yêu cầu 6: Giải mã và so sánh (tab “6. Giải mã & so sánh”)

Bấm “Mở file dữ liệu đã mã hoá…”.
Bấm “6. Giải mã bằng private key” 
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 181729" src="https://github.com/user-attachments/assets/1c918d12-b6e3-4038-96b5-81105a8f105d" />
*Ảnh này đã giải mã thành công file và cho ra kết quả trùng khớp với dữ liệu ban đầu
### Yêu cầu 7: Đánh giá tốc độ (tab “7. Tốc độ”)

Chọn 2048 bit, lặp 200 lần, bấm “7. Chạy đánh giá” 
<img width="402" height="234" alt="Ảnh chụp màn hình 2026-10-25 181934" src="https://github.com/user-attachments/assets/33b61391-1d0f-40d6-816d-89ccda310188" />
* Ảnh hiển thị tốc độ mã hóa giải mã khoá (pulic key: n, e bé), private key(n, d to đùng)
* KẾT LUẬN:
- Mã hoá (public key) nhanh vì e rất nhỏ (thường 65537 = 17 bit) → ít phép nhân bình phương.
- Giải mã/ký (private key) chậm vì d xấp xỉ bằng n (hàng nghìn bit) → số phép nhân lớn hơn hàng trăm lần.
- Khoá càng dài, phép dùng private key chậm đi rất nhanh (gần như lập phương), còn public key tăng chậm hơn.
- Thư viện còn dùng CRT (dP, dQ, qInv) để giải mã nhanh hơn so với tính m^d mod n trực tiếp.
- Vì vậy RSA chỉ dùng mã hoá dữ liệu nhỏ (khoá AES 32 byte), dữ liệu lớn mã hoá bằng AES.

### Yêu cầu 8: SHA-256 (tab “8. SHA-256”)
Trạng thái mặc định (“Hello world” so với “Hello worle”): 
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 182104" src="https://github.com/user-attachments/assets/a5b8b7f4-17e1-427f-9e66-e95df041e358" />
*Ảnh này cho thấy hai chuỗi kí tự Hello world so với Hello worle chỉ khác nhau 1 kí tự nhưng kết quả mã hóa cho băm khác hẳn nhau và số bit khác (khoảng 50%).
Bấm “Đổi 1 bit của ký tự đầu” 
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 182128" src="https://github.com/user-attachments/assets/891d13b9-1bad-4f70-bd79-e3771ab54cb9" />
*Ảnh này thay 1 kí tự của Hello worle thành Iello worle và cho ra kết ra kết quả băm

Kết luận: cho thấy dù chỉ thay đổi rất ít đầu vào nhưng kết quả băm lại thay đổi rất lớn lên tới hơn 50% giúp cho việc bảo mật thông tin đạt hiệu quả rất cao

### Yêu cầu 9: Chữ ký số (tab “9. Chữ ký số”)

Dữ liệu “Hợp đồng số 01/2026”

Chọn RSASSA-PSS, bấm “9. Ký”. 
<img width="1280" height="398" alt="Ảnh chụp màn hình 2026-10-25 182458" src="https://github.com/user-attachments/assets/79ddb16b-5091-4580-bf9f-1a370010267c" />

Ký thêm lần nữa và bấm xác minh
<img width="1280" height="800" alt="Ảnh chụp màn hình 2026-10-25 183022" src="https://github.com/user-attachments/assets/a67c3fa4-e738-410b-8002-a4aa9353e368" />
*Ảnh cho thấy tuy cùng 1 dữ liệu đầu vào cùng 1 người ký (cùng private key ) nhưng với mỗi lần ký lại cho ra mã hóa khác nhau nhưng vẫn xác minh được chữ ký đó hợp lệ và có thể biết chính xác do ai ký

#### Vậy phương pháp để đạt được hiệu quả đó là :
- Dùng RSASSA-PSS: trước khi luỹ thừa bằng d, giá trị băm được đệm với 1 salt ngẫu nhiên (mỗi lần 1 salt khác nhau)
- Người xác minh khôi phục salt từ chính chữ ký nên vẫn kiểm tra được bằng public key. Đây là cách chuẩn (RFC 8017)
