import os
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

CHUNK = 4 * 1024 * 1024  # 4 MB mỗi lần đọc -> xử lý được file hàng GB mà không tràn RAM
BLOCK = 16               # AES block size (bytes)

key = None  # khoá hiện tại (bytes)


#  KHOÁ
def generate_key(bits=256):
    return os.urandom(bits // 8)


def save_key(k, path):
    with open(path, "wb") as f:
        f.write(k)


def load_key(path):
    with open(path, "rb") as f:
        k = f.read()
    if len(k) not in (16, 24, 32):
        raise ValueError("File khoá không hợp lệ (phải dài 16/24/32 bytes)")
    return k


#  VĂN BẢN
def encrypt_text(text, k):
    iv = os.urandom(BLOCK)
    padder = padding.PKCS7(128).padder()
    data = padder.update(text.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return base64.b64encode(iv + ct).decode()  # IV đặt đầu chuỗi


def decrypt_text(b64, k):
    raw = base64.b64decode(b64)
    iv, ct = raw[:BLOCK], raw[BLOCK:]
    dec = Cipher(algorithms.AES(k), modes.CBC(iv)).decryptor()
    data = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(data) + unpadder.finalize()).decode("utf-8")


#  FILE
def encrypt_file(src, dst, k):
    """Mã hoá theo từng khối (streaming). File ra = IV (16 byte) + ciphertext."""
    iv = os.urandom(BLOCK)
    enc = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor()
    padder = padding.PKCS7(128).padder()
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(iv)
        while True:
            chunk = fi.read(CHUNK)
            if not chunk:
                break
            fo.write(enc.update(padder.update(chunk)))
        fo.write(enc.update(padder.finalize()) + enc.finalize())


def decrypt_file(src, dst, k):
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        iv = fi.read(BLOCK)
        dec = Cipher(algorithms.AES(k), modes.CBC(iv)).decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        while True:
            chunk = fi.read(CHUNK)
            if not chunk:
                break
            fo.write(unpadder.update(dec.update(chunk)))
        fo.write(unpadder.update(dec.finalize()) + unpadder.finalize())


def compare_files(a, b):
    """So sánh 2 file theo từng byte. Trả về (giống_nhau, vị_trí_khác_đầu_tiên)."""
    if os.path.getsize(a) != os.path.getsize(b):
        return False, "khác kích thước"
    pos = 0
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            x, y = fa.read(CHUNK), fb.read(CHUNK)
            if not x and not y:
                return True, None
            if x != y:
                for i in range(len(x)):
                    if x[i] != y[i]:
                        return False, pos + i
            pos += len(x)


def create_test_file(path, size_mb):
    """Tạo file dữ liệu ngẫu nhiên kích thước size_mb (MB)."""
    remaining = int(size_mb * 1024 * 1024)
    with open(path, "wb") as f:
        while remaining > 0:
            n = min(CHUNK, remaining)
            f.write(os.urandom(n))
            remaining -= n


def fmt_size(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.2f} {u}"
        n /= 1024


#  MENU
def need_key():
    if key is None:
        print("!! Chưa có khoá. Hãy chọn 1 (sinh khoá) hoặc 3 (import khoá) trước.")
        return False
    return True


def menu_generate():
    global key
    bits = input("Độ dài khoá (128/192/256) [256]: ").strip() or "256"
    if bits not in ("128", "192", "256"):
        print("Giá trị không hợp lệ.")
        return
    key = generate_key(int(bits))
    print(f"Đã sinh khoá AES-{bits}. (hex) = {key.hex()}")


def menu_save():
    if not need_key():
        return
    path = input("Lưu khoá vào file [aes.key]: ").strip() or "aes.key"
    save_key(key, path)
    print("Đã lưu khoá ->", os.path.abspath(path))


def menu_import():
    global key
    path = input("Đường dẫn file khoá [aes.key]: ").strip() or "aes.key"
    try:
        key = load_key(path)
        print(f"Đã import khoá AES-{len(key)*8}.")
    except Exception as e:
        print("Lỗi:", e)


def menu_text():
    if not need_key():
        return
    text = input("Nhập đoạn văn bản cần mã hoá: ")
    c = encrypt_text(text, key)
    print("Bản mã (base64):", c)


def menu_decrypt_text():
    if not need_key():
        return
    c = input("Nhập bản mã (base64): ").strip()
    try:
        print("Bản rõ:", decrypt_text(c, key))
    except Exception as e:
        print("Giải mã thất bại (sai khoá/sai dữ liệu):", e)


def menu_encrypt_file():
    if not need_key():
        return
    src = input("File nguồn: ").strip().strip('"')
    dst = input(f"File mã hoá đầu ra [{src}.enc]: ").strip().strip('"') or src + ".enc"
    t = time.perf_counter()
    encrypt_file(src, dst, key)
    print(f"Xong. Thời gian: {time.perf_counter()-t:.3f}s -> {dst}")


def menu_decrypt_file():
    if not need_key():
        return
    src = input("File đã mã hoá: ").strip().strip('"')
    dst = input(f"File giải mã đầu ra [{src}.dec]: ").strip().strip('"') or src + ".dec"
    t = time.perf_counter()
    try:
        decrypt_file(src, dst, key)
    except Exception as e:
        print("Giải mã thất bại (sai khoá/file hỏng):", e)
        return
    print(f"Xong. Thời gian: {time.perf_counter()-t:.3f}s -> {dst}")


def menu_benchmark():
    if not need_key():
        return
    print("1) Dùng file có sẵn   2) Tạo file thử nghiệm ngẫu nhiên")
    ch = input("Chọn [2]: ").strip() or "2"
    if ch == "1":
        src = input("File nguồn: ").strip().strip('"')
    else:
        gb = float(input("Kích thước (GB) [1]: ").strip() or "1")
        src = "test_source.bin"
        print(f"Đang tạo file {gb} GB ...")
        create_test_file(src, gb * 1024)
    enc, dec = src + ".enc", src + ".dec"
    size = os.path.getsize(src)

    print("Đang mã hoá ...")
    t0 = time.perf_counter()
    encrypt_file(src, enc, key)
    t_enc = time.perf_counter() - t0

    print("Đang giải mã ...")
    t0 = time.perf_counter()
    decrypt_file(enc, dec, key)
    t_dec = time.perf_counter() - t0

    print("Đang so sánh theo bytes ...")
    same, diff = compare_files(src, dec)

    mb = size / 1024 / 1024
    print("\n KẾT QUẢ ")
    print(f"Thuật toán      : AES-{len(key)*8}-CBC, PKCS7, chunk {CHUNK//1024//1024} MB")
    print(f"File nguồn      : {src} ({fmt_size(size)})")
    print(f"File mã hoá     : {fmt_size(os.path.getsize(enc))}")
    print(f"Thời gian mã hoá: {t_enc:.3f} s  ({mb/t_enc:.1f} MB/s)")
    print(f"Thời gian giải mã: {t_dec:.3f} s  ({mb/t_dec:.1f} MB/s)")
    print(f"So sánh bytes   : {'GIỐNG HỆT' if same else 'KHÁC tại ' + str(diff)}")
    print("\nKết luận:")
    print(f" - AES xử lý {fmt_size(size)} với tốc độ ~{mb/t_enc:.0f} MB/s (mã hoá), ~{mb/t_dec:.0f} MB/s (giải mã).")
    print(f" - File mã hoá lớn hơn nguồn {os.path.getsize(enc)-size} bytes (16 byte IV + padding).")
    print(" - File giải mã trùng khớp từng byte với file gốc => mã hoá/giải mã đúng." if same
          else " - File giải mã KHÁC file gốc => có lỗi.")
    
MENU = """
 1. Sinh khoá AES
 2. Lưu khoá ra file
 3. Import khoá từ file
 4. Mã hoá đoạn văn bản 
 5. Giải mã đoạn văn bản
 6. Mã hoá 1 file(lưu vào 1 file)
 7. Giải mã 1 file
 8. Thử nghiệm file lớn (thời gian + so sánh bytes)
 0. Thoát"""
ACTIONS = {"1": menu_generate, "2": menu_save, "3": menu_import, "4": menu_text,
           "5": menu_decrypt_text, "6": menu_encrypt_file, "7": menu_decrypt_file,
           "8": menu_benchmark}

if __name__ == "__main__":
    while True:
        print(MENU)
        c = input("Chọn: ").strip()
        if c == "0":
            break
        fn = ACTIONS.get(c)
        if fn:
            try:
                fn()
            except Exception as e:
                print("Lỗi:", e)
        else:
            print("Lựa chọn không hợp lệ.")
