using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

namespace RsaApp.Core;

/// <summary>Nút trong cây ASN.1 DER.</summary>
public class AsnNode
{
    public int Tag, Offset, HeaderLen, Length;
    public byte[] Data;
    public List<AsnNode> Children = new();
    public bool Nested;          // BIT STRING / OCTET STRING chứa 1 cấu trúc DER bên trong
    public string Label = "";    // ý nghĩa của trường (n, e, d, ...)
    public int ContentStart => Offset + HeaderLen;
    public int End => Offset + HeaderLen + Length;
}

/// <summary>Đọc file PEM, giải mã base64 -> DER và giải thích từng byte.</summary>
public static class AsnViewer
{
    static readonly Dictionary<int, string> TagNames = new()
    {
        [0x02] = "INTEGER", [0x03] = "BIT STRING", [0x04] = "OCTET STRING",
        [0x05] = "NULL", [0x06] = "OBJECT IDENTIFIER", [0x30] = "SEQUENCE"
    };

    static AsnNode ParseNode(byte[] d, int pos, int end)
    {
        if (pos + 2 > end) throw new FormatException("DER bị cắt cụt");
        int tag = d[pos];
        int p = pos + 1;
        int len = d[p++];
        if ((len & 0x80) != 0)
        {
            int n = len & 0x7F;
            if (n == 0 || n > 4 || p + n > end) throw new FormatException("Độ dài DER không hợp lệ");
            len = 0;
            for (int i = 0; i < n; i++) len = (len << 8) | d[p++];
        }
        if (len < 0 || p + len > end) throw new FormatException("Độ dài vượt quá dữ liệu");

        var node = new AsnNode { Tag = tag, Offset = pos, HeaderLen = p - pos, Length = len, Data = d };
        if ((tag & 0x20) != 0) // constructed (SEQUENCE...)
        {
            int q = p;
            while (q < p + len)
            {
                var c = ParseNode(d, q, p + len);
                node.Children.Add(c);
                q = c.End;
            }
        }
        else if ((tag == 0x03 || tag == 0x04) && len > 1)
        {
            int start = p + (tag == 0x03 ? 1 : 0);
            if (start < p + len && d[start] == 0x30)
            {
                try
                {
                    var c = ParseNode(d, start, p + len);
                    if (c.End == p + len) { node.Children.Add(c); node.Nested = true; }
                }
                catch { /* không phải cấu trúc lồng nhau */ }
            }
        }
        return node;
    }

    static readonly string[] PrivNames =
    {
        "version (0 = two-prime)", "n = modulus (p·q)", "e = publicExponent",
        "d = privateExponent (e·d ≡ 1 mod φ(n))", "p = prime1", "q = prime2",
        "dP = d mod (p-1)", "dQ = d mod (q-1)", "qInv = q⁻¹ mod p"
    };

    static void LabelTree(AsnNode n)
    {
        var ch = n.Children;
        if (n.Tag == 0x30)
        {
            if (ch.Count == 9 && ch.All(c => c.Tag == 2))
                for (int i = 0; i < 9; i++) ch[i].Label = PrivNames[i];
            else if (ch.Count == 2 && ch.All(c => c.Tag == 2))
            { ch[0].Label = "n = modulus"; ch[1].Label = "e = publicExponent"; }
            else if (ch.Count == 3 && ch[0].Tag == 2 && ch[1].Tag == 0x30 && ch[2].Tag == 4)
            {
                ch[0].Label = "version"; ch[1].Label = "privateKeyAlgorithm";
                ch[2].Label = "privateKey (chứa RSAPrivateKey kiểu PKCS#1)";
            }
            else if (ch.Count == 2 && ch[0].Tag == 0x30 && ch[1].Tag == 3)
            {
                ch[0].Label = "algorithm"; ch[1].Label = "subjectPublicKey (chứa RSAPublicKey kiểu PKCS#1)";
            }
            else if (ch.Count == 2 && ch[0].Tag == 6 && ch[1].Tag == 5)
            { ch[0].Label = "thuật toán (OID)"; ch[1].Label = "tham số (không có)"; }
        }
        foreach (var c in ch) LabelTree(c);
    }

    static string Hex(byte[] d, int off, int len, int max = int.MaxValue)
    {
        int n = Math.Min(len, max);
        var s = BitConverter.ToString(d, off, n).Replace('-', ' ');
        return len > max ? s + $" ... (+{len - max} byte)" : s;
    }

    static string DecodeOid(byte[] d, int off, int len)
    {
        var parts = new List<string> { (d[off] / 40).ToString(), (d[off] % 40).ToString() };
        long v = 0;
        for (int i = 1; i < len; i++)
        {
            v = (v << 7) | (uint)(d[off + i] & 0x7F);
            if ((d[off + i] & 0x80) == 0) { parts.Add(v.ToString()); v = 0; }
        }
        string oid = string.Join(".", parts);
        return oid == "1.2.840.113549.1.1.1" ? oid + "  (rsaEncryption)" : oid;
    }

    static string TagName(int tag) =>
        TagNames.TryGetValue(tag, out var s) ? s : $"TAG 0x{tag:X2}";

    static string HeaderMeaning(AsnNode n)
    {
        var d = n.Data;
        string t = $"{d[n.Offset]:X2} = {TagName(n.Tag)}";
        int b = d[n.Offset + 1];
        if (b < 0x80) return $"{t}; {b:X2} = độ dài {n.Length} byte";
        int k = b & 0x7F;
        return $"{t}; {b:X2} = độ dài nằm trong {k} byte kế tiếp; " +
               $"{Hex(d, n.Offset + 2, k)} = {n.Length} byte";
    }

    static void Write(StringBuilder sb, AsnNode n, int depth)
    {
        string ind = new string(' ', depth * 4);
        var d = n.Data;
        sb.Append(ind).Append($"[offset {n.Offset,4}] {TagName(n.Tag)}  (độ dài nội dung {n.Length} byte)");
        if (n.Label != "") sb.Append("   <== ").Append(n.Label);
        sb.AppendLine();
        sb.Append(ind).AppendLine("   byte tiêu đề: " + Hex(d, n.Offset, n.HeaderLen) + "   →  " + HeaderMeaning(n));

        int cs = n.ContentStart;
        switch (n.Tag)
        {
            case 0x02: // INTEGER
                {
                    bool lead0 = n.Length > 1 && d[cs] == 0 && (d[cs + 1] & 0x80) != 0;
                    var v = new BigInteger(d.AsSpan(cs, n.Length), isUnsigned: false, isBigEndian: true);
                    sb.Append(ind).AppendLine("   giá trị     : " + Hex(d, cs, n.Length, 24));
                    sb.Append(ind).AppendLine($"   số bit      : {v.GetBitLength()}" +
                        (n.Length <= 8 ? $"   |  thập phân = {v}" : "") +
                        (lead0 ? "   |  byte 00 đầu tiên chỉ để số luôn là số dương" : ""));
                    break;
                }
            case 0x06:
                sb.Append(ind).AppendLine("   giá trị     : " + DecodeOid(d, cs, n.Length) + "   (hex " + Hex(d, cs, n.Length) + ")");
                break;
            case 0x05:
                sb.Append(ind).AppendLine("   giá trị     : (NULL, không có nội dung)");
                break;
            case 0x03:
                sb.Append(ind).AppendLine($"   byte đầu = {d[cs]:X2} : số bit thừa ở cuối = {d[cs]}; phần còn lại là nội dung DER lồng bên trong");
                break;
            case 0x04:
                if (n.Nested) sb.Append(ind).AppendLine("   nội dung là 1 cấu trúc DER lồng bên trong (xem bên dưới)");
                break;
        }
        foreach (var c in n.Children) Write(sb, c, depth + 1);
    }

    static string LabelMeaning(string label) => label switch
    {
        "PUBLIC KEY" => "SubjectPublicKeyInfo (X.509) – gồm OID thuật toán + RSAPublicKey",
        "RSA PUBLIC KEY" => "RSAPublicKey kiểu PKCS#1 – chỉ gồm n, e",
        "PRIVATE KEY" => "PrivateKeyInfo (PKCS#8) – gồm OID thuật toán + RSAPrivateKey",
        "RSA PRIVATE KEY" => "RSAPrivateKey kiểu PKCS#1 – gồm version, n, e, d, p, q, dP, dQ, qInv",
        "ENCRYPTED PRIVATE KEY" => "PKCS#8 đã mã hoá bằng mật khẩu (không phân tích được nếu chưa giải mã)",
        _ => "loại PEM khác"
    };

    public static string Describe(string pem)
    {
        var m = Regex.Match(pem, @"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", RegexOptions.Singleline);
        if (!m.Success) throw new FormatException("Không phải định dạng PEM hợp lệ (thiếu dòng BEGIN/END).");
        string label = m.Groups[1].Value;
        string b64 = Regex.Replace(m.Groups[2].Value, @"\s", "");
        byte[] der = Convert.FromBase64String(b64);

        var sb = new StringBuilder();
        sb.AppendLine("=== CẤU TRÚC FILE PEM ===");
        sb.AppendLine($"-----BEGIN {label}-----   : dòng mở đầu, cho biết loại dữ liệu");
        sb.AppendLine($"   → {LabelMeaning(label)}");
        sb.AppendLine($"(các dòng giữa)           : dữ liệu nhị phân DER mã hoá Base64, mỗi dòng 64 ký tự");
        sb.AppendLine($"   → {b64.Length} ký tự Base64 = {der.Length} byte DER");
        sb.AppendLine($"-----END {label}-----     : dòng kết thúc");
        sb.AppendLine();
        sb.AppendLine("=== CÁC BYTE DER VÀ Ý NGHĨA (mỗi trường = Tag | Length | Value) ===");
        sb.AppendLine("Tag: 30=SEQUENCE, 02=INTEGER, 03=BIT STRING, 04=OCTET STRING, 05=NULL, 06=OID");
        sb.AppendLine("Length: <0x80 là độ dài luôn; 81/82/83 nghĩa là độ dài nằm trong 1/2/3 byte tiếp theo");
        sb.AppendLine();

        var root = ParseNode(der, 0, der.Length);
        LabelTree(root);
        Write(sb, root, 0);
        return sb.ToString();
    }
}
