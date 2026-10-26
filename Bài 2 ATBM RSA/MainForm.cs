using System.Security.Cryptography;
using System.Text;
using RsaApp.Core;

namespace RsaApp;

public class MainForm : Form
{
    // ---- trạng thái dùng chung giữa các tab
    RSA genKey;          // cặp khoá vừa sinh (tab 1)
    RSA pubKey;          // public key đã import từ file PEM (tab 3)
    RSA privKey;         // private key đã import từ file PEM (tab 3)
    string lastPlainB64 = "";

    // ---- tab 1
    ComboBox cbBits; CheckBox chkPkcs1; TextBox txtPubPem, txtPrivPem;
    // ---- tab 2
    TextBox txtPemIn, txtPemOut;
    // ---- tab 3
    TextBox txtImport; Label lblImportStatus;
    // ---- tab 4
    ComboBox cbInType; TextBox txtPlain, txtCipher; Label lblEncInfo;
    // ---- tab 5
    TextBox txtCipherIn, txtDecrypted, txtOriginal; Label lblCompare;
    // ---- tab 6
    ComboBox cbBenchBits; NumericUpDown numIter; TextBox txtBench; Button btnBench, btnBenchAll;
    // ---- tab 7
    TextBox txtA, txtB, txtHashA, txtHashB; Label lblDiff;
    // ---- tab 8
    ComboBox cbMode; TextBox txtSignData, txtSignature, txtSignLog;

    static readonly Font Mono = new("Consolas", 10);
    static readonly Font Bold = new("Segoe UI", 9, FontStyle.Bold);

    public MainForm()
    {
        Text = "Mã hoá RSA (bất đối xứng)";
        Size = new Size(1150, 780);
        StartPosition = FormStartPosition.CenterScreen;

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(TabKeys());
        tabs.TabPages.Add(TabViewPem());
        tabs.TabPages.Add(TabImport());
        tabs.TabPages.Add(TabEncrypt());
        tabs.TabPages.Add(TabDecrypt());
        tabs.TabPages.Add(TabBench());
        tabs.TabPages.Add(TabSha());
        tabs.TabPages.Add(TabSign());
        Controls.Add(tabs);
    }

    // ============================================================ HELPER GIAO DIỆN
    static TextBox Box(bool readOnly = false, bool wrap = true) => new()
    {
        Multiline = true, ReadOnly = readOnly, Font = Mono, Dock = DockStyle.Fill,
        ScrollBars = wrap ? ScrollBars.Vertical : ScrollBars.Both, WordWrap = wrap
    };

    static Button Btn(string text, EventHandler click)
    {
        var b = new Button { Text = text, AutoSize = true, Padding = new Padding(6, 2, 6, 2) };
        b.Click += click;
        return b;
    }

    static Label Lbl(string text) => new() { Text = text, AutoSize = true, Margin = new Padding(8, 8, 3, 0) };

    static FlowLayoutPanel Bar(params Control[] items)
    {
        var f = new FlowLayoutPanel
        {
            Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            WrapContents = true, Padding = new Padding(4)
        };
        f.Controls.AddRange(items);
        return f;
    }

    static Control Labeled(string caption, Control c)
    {
        var p = new Panel { Dock = DockStyle.Fill };
        var l = new Label { Text = caption, Dock = DockStyle.Top, Height = 22, Font = Bold, TextAlign = ContentAlignment.BottomLeft };
        p.Controls.Add(c);
        p.Controls.Add(l);
        return p;
    }

    static TableLayoutPanel Grid(bool horizontal, params Control[] items)
    {
        var t = new TableLayoutPanel { Dock = DockStyle.Fill };
        if (horizontal)
        {
            t.ColumnCount = items.Length; t.RowCount = 1;
            t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            foreach (var it in items) { t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / items.Length)); it.Dock = DockStyle.Fill; t.Controls.Add(it); }
        }
        else
        {
            t.ColumnCount = 1; t.RowCount = items.Length;
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            foreach (var it in items) { t.RowStyles.Add(new RowStyle(SizeType.Percent, 100f / items.Length)); it.Dock = DockStyle.Fill; t.Controls.Add(it); }
        }
        return t;
    }

    static TabPage Page(string title, Control body, Control top)
    {
        var tp = new TabPage(title) { Padding = new Padding(4) };
        tp.Controls.Add(body);   // Fill thêm trước
        tp.Controls.Add(top);    // Top thêm sau => nằm phía trên
        return tp;
    }

    static void Info(string m) => MessageBox.Show(m, "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
    static void Err(string m) => MessageBox.Show(m, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);

    RSA PickPublic() => pubKey ?? genKey;
    RSA PickPrivate() => privKey ?? genKey;

    // ============================================================ TAB 1: SINH KHOÁ
    TabPage TabKeys()
    {
        cbBits = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 80 };
        cbBits.Items.AddRange(new object[] { 1024, 2048, 3072, 4096 });
        cbBits.SelectedIndex = 1;
        chkPkcs1 = new CheckBox { Text = "Xuất dạng PKCS#1 (RSA PUBLIC/PRIVATE KEY) thay vì X.509/PKCS#8", AutoSize = true, Margin = new Padding(12, 8, 3, 0) };
        txtPubPem = Box(true, false);
        txtPrivPem = Box(true, false);

        var bar = Bar(Lbl("Độ dài khoá (bit):"), cbBits,
            Btn("1. Sinh cặp khoá", async (s, e) => await GenerateKeys()),
            Btn("2. Xuất ra file PEM…", (s, e) => ExportPem()), chkPkcs1);
        var body = Grid(true, Labeled("Public key (PEM)", txtPubPem), Labeled("Private key (PEM) ", txtPrivPem));
        return Page("1-2. Sinh & xuất khoá", body, bar);
    }

    async Task GenerateKeys()
    {
        int bits = (int)cbBits.SelectedItem;
        Cursor = Cursors.WaitCursor;
        try
        {
            var k = await Task.Run(() => { var r = RsaHelper.Generate(bits); r.ExportParameters(true); return r; });
            genKey?.Dispose();
            genKey = k;
            ShowPems();
        }
        catch (Exception ex) { Err(ex.Message); }
        finally { Cursor = Cursors.Default; }
    }

    void ShowPems()
    {
        if (genKey == null) return;
        txtPubPem.Text = RsaHelper.ExportPublicPem(genKey, chkPkcs1.Checked);
        txtPrivPem.Text = RsaHelper.ExportPrivatePem(genKey, chkPkcs1.Checked);
    }

    void ExportPem()
    {
        if (genKey == null) { Err("Chưa sinh khoá."); return; }
        ShowPems();
        using var fb = new FolderBrowserDialog { Description = "Chọn thư mục lưu public.pem và private.pem" };
        if (fb.ShowDialog() != DialogResult.OK) return;
        File.WriteAllText(Path.Combine(fb.SelectedPath, "public.pem"), txtPubPem.Text);
        File.WriteAllText(Path.Combine(fb.SelectedPath, "private.pem"), txtPrivPem.Text);
        Info("Đã lưu public.pem và private.pem vào:\n" + fb.SelectedPath);
    }

    // ============================================================ TAB 2: XEM PEM
    TabPage TabViewPem()
    {
        txtPemIn = Box(false, false);
        txtPemOut = Box(true, false);
        var bar = Bar(
            Btn("Mở file PEM…", (s, e) => { var t = ReadPemFile(); if (t != null) { txtPemIn.Text = t; Analyze(); } }),
            Btn("Lấy public key vừa sinh", (s, e) => { if (genKey == null) Err("Chưa sinh khoá."); else { txtPemIn.Text = RsaHelper.ExportPublicPem(genKey, chkPkcs1.Checked); Analyze(); } }),
            Btn("Lấy private key vừa sinh", (s, e) => { if (genKey == null) Err("Chưa sinh khoá."); else { txtPemIn.Text = RsaHelper.ExportPrivatePem(genKey, chkPkcs1.Checked); Analyze(); } }),
            Btn("3. Phân tích PEM", (s, e) => Analyze()));
        var body = Grid(false, Labeled("Nội dung PEM (dán hoặc mở file)", txtPemIn), Labeled("Ý nghĩa các byte trong định dạng PEM / DER", txtPemOut));
        ((TableLayoutPanel)body).RowStyles[0].Height = 25;
        ((TableLayoutPanel)body).RowStyles[1].Height = 75;
        return Page("3. Xem PEM", body, bar);
    }

    void Analyze()
    {
        try { txtPemOut.Text = AsnViewer.Describe(txtPemIn.Text); }
        catch (Exception ex) { Err(ex.Message); }
    }

    static string ReadPemFile()
    {
        using var ofd = new OpenFileDialog { Filter = "PEM|*.pem;*.key;*.txt|Tất cả|*.*" };
        return ofd.ShowDialog() == DialogResult.OK ? File.ReadAllText(ofd.FileName) : null;
    }

    // ============================================================ TAB 3: IMPORT
    TabPage TabImport()
    {
        txtImport = Box(true, true);
        lblImportStatus = new Label { AutoSize = true, Margin = new Padding(12, 8, 3, 0), Text = "Chưa import khoá nào." };
        var bar = Bar(
            Btn("4a. Nhập file PEM public key → n, e", (s, e) => ImportKey(false)),
            Btn("4b. Nhập file PEM private key → n, e, d, p, q…", (s, e) => ImportKey(true)),
            lblImportStatus);
        return Page("4. Import PEM", Labeled("Thông số đọc được từ file PEM", txtImport), bar);
    }

    void ImportKey(bool wantPrivate)
    {
        var pem = ReadPemFile();
        if (pem == null) return;
        try
        {
            var rsa = RsaHelper.ImportPem(pem, out bool isPriv);
            if (wantPrivate && !isPriv) { Err("File này là PUBLIC key, hãy chọn file private key."); return; }
            if (!wantPrivate && isPriv) { Err("File này là PRIVATE key, hãy chọn file public key."); return; }
            if (wantPrivate) { privKey?.Dispose(); privKey = rsa; }
            else { pubKey?.Dispose(); pubKey = rsa; }
            txtImport.Text = (wantPrivate ? "=== PRIVATE KEY ===\r\n" : "=== PUBLIC KEY ===\r\n") + RsaHelper.DescribeKey(rsa, wantPrivate);
            lblImportStatus.Text = $"Đã import: public={(pubKey != null ? "có" : "chưa")}, private={(privKey != null ? "có" : "chưa")}";
        }
        catch (Exception ex) { Err("Không đọc được PEM: " + ex.Message); }
    }

    // ============================================================ TAB 4: MÃ HOÁ
    TabPage TabEncrypt()
    {
        cbInType = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 130 };
        cbInType.Items.AddRange(new object[] { "Base64 (mảng byte)", "Văn bản UTF-8" });
        cbInType.SelectedIndex = 0;
        lblEncInfo = new Label { AutoSize = true, Margin = new Padding(12, 8, 3, 0) };
        txtPlain = Box(false, true);
        txtCipher = Box(true, true);
        txtPlain.TextChanged += (s, e) => UpdateEncInfo();

        var bar = Bar(
            Btn("Sinh khoá AES-256 (32 byte)", (s, e) =>
            {
                cbInType.SelectedIndex = 0;
                txtPlain.Text = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            }),
            Lbl("Kiểu dữ liệu nhập:"), cbInType,
            Btn("5. Mã hoá bằng public key", (s, e) => DoEncrypt()),
            Btn("Lưu kết quả ra file…", (s, e) => SaveCipher()),
            lblEncInfo);
        var body = Grid(false,
            Labeled("Dữ liệu cần mã hoá (mảng byte, tối đa 190 byte với RSA-2048 OAEP-SHA256)", txtPlain),
            Labeled("Kết quả mã hoá (Base64)", txtCipher));
        return Page("5. Mã hoá", body, bar);
    }

    byte[] GetPlainBytes()
    {
        return cbInType.SelectedIndex == 0
            ? Convert.FromBase64String(txtPlain.Text.Trim())
            : Encoding.UTF8.GetBytes(txtPlain.Text);
    }

    void UpdateEncInfo()
    {
        try { lblEncInfo.Text = $"Độ dài: {GetPlainBytes().Length} byte"; }
        catch { lblEncInfo.Text = "Base64 không hợp lệ"; }
    }

    void DoEncrypt()
    {
        var pub = PickPublic();
        if (pub == null) { Err("Chưa có public key. Hãy import ở tab 4 (hoặc sinh khoá ở tab 1)."); return; }
        try
        {
            var data = GetPlainBytes();
            lastPlainB64 = Convert.ToBase64String(data);
            var c = RsaHelper.Encrypt(pub, data);
            txtCipher.Text = Convert.ToBase64String(c);
            lblEncInfo.Text = $"Đầu vào {data.Length} byte → bản mã {c.Length} byte " +
                              $"(dùng {(pubKey != null ? "public key đã import" : "khoá vừa sinh")}, giới hạn {RsaHelper.MaxPlainBytes(pub)} byte)";
            txtOriginal.Text = lastPlainB64;
            txtCipherIn.Text = txtCipher.Text;
        }
        catch (Exception ex) { Err(ex.Message); }
    }

    void SaveCipher()
    {
        if (txtCipher.Text.Length == 0) { Err("Chưa có kết quả mã hoá."); return; }
        using var sfd = new SaveFileDialog { FileName = "encrypted.txt", Filter = "Text|*.txt|Tất cả|*.*" };
        if (sfd.ShowDialog() == DialogResult.OK) File.WriteAllText(sfd.FileName, txtCipher.Text);
    }

    // ============================================================ TAB 5: GIẢI MÃ
    TabPage TabDecrypt()
    {
        txtCipherIn = Box(false, true);
        txtDecrypted = Box(true, true);
        txtOriginal = Box(false, true);
        lblCompare = new Label { AutoSize = true, Margin = new Padding(12, 8, 3, 0), Font = Bold };
        var bar = Bar(
            Btn("Mở file dữ liệu đã mã hoá…", (s, e) =>
            {
                using var ofd = new OpenFileDialog { Filter = "Text|*.txt|Tất cả|*.*" };
                if (ofd.ShowDialog() == DialogResult.OK) txtCipherIn.Text = File.ReadAllText(ofd.FileName).Trim();
            }),
            Btn("6. Giải mã bằng private key", (s, e) => DoDecrypt()),
            lblCompare);
        var body = Grid(false,
            Labeled("Dữ liệu đã mã hoá (Base64)", txtCipherIn),
            Labeled("Kết quả giải mã (Base64)", txtDecrypted),
            Labeled("Dữ liệu gốc trước khi mã hoá (Base64) – để so sánh", txtOriginal));
        return Page("6. Giải mã & so sánh", body, bar);
    }

    void DoDecrypt()
    {
        var priv = PickPrivate();
        if (priv == null) { Err("Chưa có private key. Hãy import ở tab 4 (hoặc sinh khoá ở tab 1)."); return; }
        try
        {
            var c = Convert.FromBase64String(txtCipherIn.Text.Trim());
            var plain = RsaHelper.Decrypt(priv, c);
            txtDecrypted.Text = Convert.ToBase64String(plain);
            var orig = Convert.FromBase64String(txtOriginal.Text.Trim());
            bool same = orig.SequenceEqual(plain);
            lblCompare.Text = same ? $"✔ TRÙNG KHỚP với dữ liệu gốc ({plain.Length} byte)" : "✘ KHÁC dữ liệu gốc";
            lblCompare.ForeColor = same ? Color.ForestGreen : Color.Firebrick;
        }
        catch (CryptographicException) { Err("Giải mã thất bại: private key không khớp với public key đã dùng để mã hoá, hoặc dữ liệu bị sửa."); }
        catch (Exception ex) { Err(ex.Message); }
    }

    //  TAB 6: TỐC ĐỘ
    TabPage TabBench()
    {
        cbBenchBits = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 80 };
        cbBenchBits.Items.AddRange(new object[] { 1024, 2048, 3072, 4096 });
        cbBenchBits.SelectedIndex = 1;
        numIter = new NumericUpDown { Minimum = 10, Maximum = 5000, Value = 200, Width = 70, Increment = 50 };
        txtBench = Box(true, false);
        btnBench = Btn("7. Chạy đánh giá", async (s, e) => await RunBench(new[] { (int)cbBenchBits.SelectedItem }));
        btnBenchAll = Btn("Chạy cả 4 độ dài khoá", async (s, e) => await RunBench(new[] { 1024, 2048, 3072, 4096 }));
        var bar = Bar(Lbl("Độ dài khoá:"), cbBenchBits, Lbl("Số lần lặp:"), numIter, btnBench, btnBenchAll);
        return Page("7. Tốc độ", Labeled("Kết quả: public key (e nhỏ) so với private key (d lớn)", txtBench), bar);
    }

    async Task RunBench(int[] sizes)
    {
        btnBench.Enabled = btnBenchAll.Enabled = false;
        txtBench.Text = "Đang chạy…\r\n";
        int iter = (int)numIter.Value;
        try
        {
            var sb = new StringBuilder();
            foreach (int bits in sizes)
            {
                string r = await Task.Run(() => RsaHelper.Benchmark(bits, iter));
                sb.Append(r.Replace("\n", "\r\n").Replace("\r\r\n", "\r\n"));
                txtBench.Text = sb + "Đang chạy…";
            }
            txtBench.Text = sb.ToString();
        }
        catch (Exception ex) { Err(ex.Message); txtBench.Text = ""; }
        finally { btnBench.Enabled = btnBenchAll.Enabled = true; }
    }

    //  TAB 7: SHA-256
    TabPage TabSha()
    {
        txtA = Box(false, true); txtB = Box(false, true);
        txtHashA = Box(true, true); txtHashB = Box(true, true);
        lblDiff = new Label { AutoSize = true, Margin = new Padding(12, 8, 3, 0), Font = Bold };
        txtA.Text = "Hello world";
        txtB.Text = "Hello worle";
        txtA.TextChanged += (s, e) => UpdateHash();
        txtB.TextChanged += (s, e) => UpdateHash();
        var bar = Bar(
            Btn("Đổi 1 bit của ký tự đầu (A → B)", (s, e) =>
            {
                if (txtA.Text.Length == 0) return;
                txtB.Text = (char)(txtA.Text[0] ^ 1) + txtA.Text.Substring(1);
            }),
            lblDiff);
        var left = Grid(false, Labeled("Dữ liệu A", txtA), Labeled("SHA-256(A) – 256 bit (hex)", txtHashA));
        var right = Grid(false, Labeled("Dữ liệu B", txtB), Labeled("SHA-256(B) – 256 bit (hex)", txtHashB));
        UpdateHash();
        return Page("8. SHA-256", Grid(true, left, right), bar);
    }

    void UpdateHash()
    {
        var a = RsaHelper.Sha256(txtA.Text);
        var b = RsaHelper.Sha256(txtB.Text);
        txtHashA.Text = Convert.ToHexString(a);
        txtHashB.Text = Convert.ToHexString(b);
        int d = RsaHelper.DiffBits(a, b);
        lblDiff.Text = $"Hai giá trị băm khác nhau {d}/256 bit = {d * 100.0 / 256:F1}%  (kỳ vọng ≈ 50% – hiệu ứng thác đổ)";
    }

    //  TAB 8: CHỮ KÝ SỐ
    TabPage TabSign()
    {
        cbMode = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 330 };
        cbMode.Items.AddRange(new object[]
        {
            "PKCS#1 v1.5 (xác định – cùng dữ liệu luôn ra cùng chữ ký)",
            "RSASSA-PSS (đệm có salt ngẫu nhiên)",
            "PKCS#1 + nonce + timestamp ghép vào dữ liệu"
        });
        cbMode.SelectedIndex = 1;
        txtSignData = Box(false, true);
        txtSignData.Text = "Hợp đồng số 01/2026";
        txtSignature = Box(false, false);
        txtSignLog = Box(true, true);

        var bar = Bar(Lbl("Phương pháp:"), cbMode,
            Btn("9. Ký (private key)", (s, e) => DoSign()),
            Btn("Xác minh (public key)", (s, e) => DoVerify()),
            Btn("So sánh 3 phương pháp (mỗi cách ký 3 lần)", (s, e) => CompareSigning()));
        var body = Grid(false,
            Labeled("Dữ liệu cần ký", txtSignData),
            Labeled("Chữ ký số (Base64)", txtSignature),
            Labeled("Nhật ký ", txtSignLog));
        ((TableLayoutPanel)body).RowStyles[0].Height = 20;
        ((TableLayoutPanel)body).RowStyles[1].Height = 30;
        ((TableLayoutPanel)body).RowStyles[2].Height = 50;
        txtSignLog.Text =
            "  Log hệ thống\r\n";
        return Page("9. Chữ ký số", body, bar);
    }

    SignMode CurMode => (SignMode)cbMode.SelectedIndex;

    void DoSign()
    {
        var priv = PickPrivate();
        if (priv == null) { Err("Chưa có private key (sinh ở tab 1 hoặc import ở tab 4)."); return; }
        try
        {
            var data = Encoding.UTF8.GetBytes(txtSignData.Text);
            txtSignature.Text = RsaHelper.Sign(priv, data, CurMode);
            txtSignLog.AppendText($"\r\n[{DateTime.Now:HH:mm:ss}] Đã ký bằng '{cbMode.Text}', băm SHA-256 = {Convert.ToHexString(RsaHelper.Sha256(txtSignData.Text))[..16]}…");
        }
        catch (Exception ex) { Err(ex.Message); }
    }

    void DoVerify()
    {
        var pub = PickPublic();
        if (pub == null) { Err("Chưa có public key."); return; }
        var data = Encoding.UTF8.GetBytes(txtSignData.Text);
        bool ok = RsaHelper.Verify(pub, data, txtSignature.Text.Trim(), CurMode);
        txtSignLog.AppendText($"\r\n[{DateTime.Now:HH:mm:ss}] Xác minh: {(ok ? "HỢP LỆ ✔" : "KHÔNG HỢP LỆ ✘")}");
        MessageBox.Show(ok ? "Chữ ký HỢP LỆ" : "Chữ ký KHÔNG HỢP LỆ", "Xác minh",
            MessageBoxButtons.OK, ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
    }

    void CompareSigning()
    {
        var priv = PickPrivate(); var pub = PickPublic();
        if (priv == null || pub == null) { Err("Cần có khoá (sinh ở tab 1 hoặc import)."); return; }
        var data = Encoding.UTF8.GetBytes(txtSignData.Text);
        var sb = new StringBuilder("\r\n===== SO SÁNH: ký 3 lần cùng 1 dữ liệu, cùng 1 private key =====\r\n");
        string[] names = { "PKCS#1 v1.5", "RSASSA-PSS", "PKCS#1 + nonce + timestamp" };
        foreach (SignMode m in Enum.GetValues<SignMode>())
        {
            var sigs = Enumerable.Range(0, 3).Select(_ => RsaHelper.Sign(priv, data, m)).ToList();
            bool allValid = sigs.All(x => RsaHelper.Verify(pub, data, x, m));
            sb.AppendLine($"{names[(int)m]}: {sigs.Distinct().Count()}/3 chữ ký khác nhau, xác minh {(allValid ? "đều hợp lệ" : "CÓ LỖI")}");
            foreach (var x in sigs) sb.AppendLine("    " + (x.Length > 70 ? x[..70] + "…" : x));
        }
        txtSignLog.AppendText(sb.ToString());
    }
}
