using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RsaApp.Core;

public enum SignMode { Pkcs1, Pss, NonceTimestamp }

public static class RsaHelper
{
    // ---------------------------------------------------------------- KHOÁ / PEM
    public static RSA Generate(int bits) => RSA.Create(bits);

    public static string ExportPublicPem(RSA rsa, bool pkcs1) =>
        pkcs1 ? rsa.ExportRSAPublicKeyPem() : rsa.ExportSubjectPublicKeyInfoPem();

    public static string ExportPrivatePem(RSA rsa, bool pkcs1) =>
        pkcs1 ? rsa.ExportRSAPrivateKeyPem() : rsa.ExportPkcs8PrivateKeyPem();

    public static RSA ImportPem(string pem, out bool isPrivate)
    {
        isPrivate = pem.Contains("PRIVATE KEY");
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa;
    }

    static BigInteger Big(byte[] b) => new BigInteger(b, isUnsigned: true, isBigEndian: true);

    public static string DescribeKey(RSA rsa, bool includePrivate)
    {
        var p = rsa.ExportParameters(includePrivate);
        var sb = new StringBuilder();
        sb.AppendLine($"Độ dài khoá (số bit của n): {Big(p.Modulus).GetBitLength()}");
        sb.AppendLine();
        sb.AppendLine($"n (modulus) – {p.Modulus.Length} byte:\r\n{Convert.ToHexString(p.Modulus)}\r\n");
        sb.AppendLine($"e (public exponent) = {Big(p.Exponent)}  (hex {Convert.ToHexString(p.Exponent)})\r\n");
        if (includePrivate)
        {
            sb.AppendLine($"d (private exponent) – {Big(p.D).GetBitLength()} bit:\r\n{Convert.ToHexString(p.D)}\r\n");
            sb.AppendLine($"p (prime1):\r\n{Convert.ToHexString(p.P)}\r\n");
            sb.AppendLine($"q (prime2):\r\n{Convert.ToHexString(p.Q)}\r\n");
            sb.AppendLine($"dP = d mod (p-1):\r\n{Convert.ToHexString(p.DP)}\r\n");
            sb.AppendLine($"dQ = d mod (q-1):\r\n{Convert.ToHexString(p.DQ)}\r\n");
            sb.AppendLine($"qInv = q^-1 mod p:\r\n{Convert.ToHexString(p.InverseQ)}");
            var n = Big(p.Modulus);
            bool ok = (Big(p.P) * Big(p.Q)) == n;
            sb.AppendLine($"\r\nKiểm tra: p·q == n ? {(ok ? "ĐÚNG" : "SAI")}");
        }
        return sb.ToString();
    }

    //  MÃ HOÁ / GIẢI MÃ
    /// <summary>OAEP-SHA256: số byte tối đa = k - 2*hLen - 2 = k - 66 (2048 bit -> 190 byte).</summary>
    public static int MaxPlainBytes(RSA rsa) => rsa.KeySize / 8 - 2 * 32 - 2;

    public static byte[] Encrypt(RSA pub, byte[] data)
    {
        if (data.Length > MaxPlainBytes(pub))
            throw new ArgumentException($"Dữ liệu {data.Length} byte vượt quá giới hạn {MaxPlainBytes(pub)} byte của khoá {pub.KeySize} bit.");
        return pub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    public static byte[] Decrypt(RSA priv, byte[] cipher) =>
        priv.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);

    //  SHA-256
    public static byte[] Sha256(string s) => SHA256.HashData(Encoding.UTF8.GetBytes(s ?? ""));

    public static int DiffBits(byte[] a, byte[] b)
    {
        int c = 0;
        for (int i = 0; i < a.Length; i++) c += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        return c;
    }

    // CHỮ KÝ SỐ
    public static string Sign(RSA priv, byte[] data, SignMode mode)
    {
        switch (mode)
        {
            case SignMode.Pkcs1:
                return Convert.ToBase64String(priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            case SignMode.Pss:
                return Convert.ToBase64String(priv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            default:
                string ts = DateTime.UtcNow.Ticks.ToString();
                string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                var sig = priv.SignData(WithNonce(data, ts, nonce), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return $"{ts}:{nonce}:{Convert.ToBase64String(sig)}";
        }
    }

    static byte[] WithNonce(byte[] data, string ts, string nonce) =>
        data.Concat(Encoding.UTF8.GetBytes($"|{ts}|{nonce}")).ToArray();

    public static bool Verify(RSA pub, byte[] data, string signature, SignMode mode)
    {
        try
        {
            switch (mode)
            {
                case SignMode.Pkcs1:
                    return pub.VerifyData(data, Convert.FromBase64String(signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                case SignMode.Pss:
                    return pub.VerifyData(data, Convert.FromBase64String(signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                default:
                    var parts = signature.Split(':');
                    if (parts.Length != 3) return false;
                    return pub.VerifyData(WithNonce(data, parts[0], parts[1]), Convert.FromBase64String(parts[2]),
                        HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
        catch { return false; }
    }

    //  ĐÁNH GIÁ TỐC ĐỘ
    public static string Benchmark(int bits, int iterations)
    {
        var sb = new StringBuilder();
        var sw = Stopwatch.StartNew();
        using var rsa = RSA.Create(bits);
        var p = rsa.ExportParameters(true);   // buộc sinh khoá thật sự (khởi tạo lười)
        double tGen = sw.Elapsed.TotalMilliseconds;
        BigInteger n = Big(p.Modulus), e = Big(p.Exponent), d = Big(p.D);

        // thông điệp ngẫu nhiên m < n
        var mb = RandomNumberGenerator.GetBytes(p.Modulus.Length - 1);
        BigInteger m = Big(mb);

        // ---- (1) RSA "thô": m^e mod n  và  m^d mod n
        BigInteger.ModPow(m, e, n); BigInteger.ModPow(m, d, n); // khởi động (JIT)
        sw.Restart();
        for (int i = 0; i < iterations; i++) BigInteger.ModPow(m, e, n);
        double tE = sw.Elapsed.TotalMilliseconds;
        sw.Restart();
        for (int i = 0; i < iterations; i++) BigInteger.ModPow(m, d, n);
        double tD = sw.Elapsed.TotalMilliseconds;

        // ---- (2) API chuẩn: OAEP encrypt (public) / decrypt (private, có CRT)
        byte[] data = RandomNumberGenerator.GetBytes(32);
        byte[] c = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        rsa.Decrypt(c, RSAEncryptionPadding.OaepSHA256);
        sw.Restart();
        for (int i = 0; i < iterations; i++) rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        double tEncApi = sw.Elapsed.TotalMilliseconds;
        sw.Restart();
        for (int i = 0; i < iterations; i++) rsa.Decrypt(c, RSAEncryptionPadding.OaepSHA256);
        double tDecApi = sw.Elapsed.TotalMilliseconds;

        sb.AppendLine($"===== RSA {bits} bit, {iterations} lần lặp =====");
        sb.AppendLine($"Sinh khoá: {tGen:F1} ms");
        sb.AppendLine($"e = {e} ({e.GetBitLength()} bit)   |   d có {d.GetBitLength()} bit");
        sb.AppendLine();
        sb.AppendLine("(1) Phép toán thô  m^k mod n");
        sb.AppendLine($"    Dùng PUBLIC  (n, e - nhỏ) : {tE,10:F2} ms  → {tE / iterations,8:F4} ms/lần");
        sb.AppendLine($"    Dùng PRIVATE (n, d - lớn) : {tD,10:F2} ms  → {tD / iterations,8:F4} ms/lần");
        sb.AppendLine($"    Private chậm hơn Public   : {tD / tE:F1} lần");
        sb.AppendLine();
        sb.AppendLine("(2) API chuẩn RSA-OAEP-SHA256");
        sb.AppendLine($"    Mã hoá  bằng public key   : {tEncApi,10:F2} ms  → {tEncApi / iterations,8:F4} ms/lần");
        sb.AppendLine($"    Giải mã bằng private key  : {tDecApi,10:F2} ms  → {tDecApi / iterations,8:F4} ms/lần");
        sb.AppendLine($"    Giải mã chậm hơn mã hoá   : {tDecApi / tEncApi:F1} lần");
        sb.AppendLine();
        return sb.ToString();
    }
}
