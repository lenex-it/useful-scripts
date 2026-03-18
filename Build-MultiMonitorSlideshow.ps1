#Requires -Version 5.1
<#
.SYNOPSIS
    Build-MultiMonitorSlideshow.ps1
.DESCRIPTION
    Compiles a custom multi-monitor photo slideshow screensaver (.scr) from inline C# source
    using Add-Type. One borderless window is created per display, each sized to that screen's
    exact resolution. Images are loaded from a configurable local folder.
    The output file is placed in C:\Windows\System32 so Windows picks it up automatically.
    Supports /s (run), /c (config dialog), /p (preview handle).

    NOTE: SCRNSAVE.EXE registration is intentionally NOT performed by this script.
    That key is managed by the Screenlock v1.4 deployment script.

    SlideIntervalMs and FadeDurationMs can be overridden via registry:
    HKCU\Software\Lenex\Screenlock
      SlideIntervalMs  (DWORD) — milliseconds per slide  (default: 10000)
      FadeDurationMs   (DWORD) — crossfade duration in ms (default: 0)
.AUTHOR
    Lenex IT
.VERSION
    1.4
.USAGE
    Run elevated (Administrator required to write to System32).
    .\Build-MultiMonitorSlideshow.ps1
    .\Build-MultiMonitorSlideshow.ps1 -PhotoFolder "D:\MyPhotos" -OutputName "MultiMonitorSlideshow.scr"
#>

[CmdletBinding()]
param(
    # Folder that contains the photos to display (baked into the .scr at compile time as default;
    # can be overridden via the /c config dialog which writes to HKCU registry)
    [string]$PhotoFolder = (Join-Path $env:ProgramData 'Lenex\Screenlock\Photos'),

    # Filename for the output screensaver — placed in System32
    [string]$OutputName  = 'MultiMonitorSlideshow.scr'
)

#region ── Logging ──────────────────────────────────────────────────────────────
$LogDir  = Join-Path $env:ProgramData 'Lenex\Logs'
$LogFile = Join-Path $LogDir ("Build-MultiMonitorSlideshow_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','SUCCESS','WARNING','ERROR')][string]$Level = 'INFO')
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $line
    switch ($Level) {
        'SUCCESS' { Write-Host $line -ForegroundColor Green  }
        'WARNING' { Write-Host $line -ForegroundColor Yellow }
        'ERROR'   { Write-Host $line -ForegroundColor Red    }
        default   { Write-Host $line                         }
    }
}
#endregion

#region ── Elevation check ──────────────────────────────────────────────────────
function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsElevated)) {
    Write-Log "Script must run as Administrator." ERROR
    return
}
#endregion

#region ── Inline C# source ─────────────────────────────────────────────────────
$CSharpSource = @"
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

// ── P/Invoke ────────────────────────────────────────────────────────────────
static class NativeMethods {
    [DllImport("user32.dll")] public static extern IntPtr SetParent(IntPtr child, IntPtr parent);
    [DllImport("user32.dll")] public static extern bool  SetWindowPos(IntPtr hWnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] public static extern int   SetWindowLong(IntPtr hWnd, int nIndex, int value);
    [DllImport("user32.dll")] public static extern int   GetWindowLong(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll")] public static extern bool  GetClientRect(IntPtr hWnd, out RECT rc);
    [DllImport("user32.dll")] public static extern bool  ShowCursor(bool show);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }

    public const int GWL_STYLE    = -16;
    public const int WS_CHILD     = 0x40000000;
    public const uint SWP_SHOWWINDOW = 0x0040;
}

// ── Registry helpers / Settings ──────────────────────────────────────────────
static class Settings {
    private const string RegPath = @"Software\Lenex\Screenlock";

    // Default photo folder is baked in at compile time via placeholder
    private static readonly string DefaultFolder = @"%%PHOTO_FOLDER%%";

    // Default timing values baked in at compile time
    private const int DefaultSlideIntervalMs = %%SLIDE_INTERVAL_MS%%;
    private const int DefaultFadeDurationMs  = %%FADE_DURATION_MS%%;

    public static string PhotoFolder {
        get {
            using (var k = Registry.CurrentUser.OpenSubKey(RegPath))
                return k != null ? k.GetValue("PhotoFolder") as string ?? DefaultFolder : DefaultFolder;
        }
        set {
            using (var k = Registry.CurrentUser.CreateSubKey(RegPath))
                k.SetValue("PhotoFolder", value, RegistryValueKind.String);
        }
    }

    // SlideIntervalMs: read from HKCU registry if present, otherwise fall back to compiled-in default
    public static int SlideIntervalMs {
        get {
            using (var k = Registry.CurrentUser.OpenSubKey(RegPath)) {
                var v = k != null ? k.GetValue("SlideIntervalMs") : null;
                return (v != null) ? Convert.ToInt32(v) : DefaultSlideIntervalMs;
            }
        }
    }

    // FadeDurationMs: read from HKCU registry if present, otherwise fall back to compiled-in default
    public static int FadeDurationMs {
        get {
            using (var k = Registry.CurrentUser.OpenSubKey(RegPath)) {
                var v = k != null ? k.GetValue("FadeDurationMs") : null;
                return (v != null) ? Convert.ToInt32(v) : DefaultFadeDurationMs;
            }
        }
    }
}

// ── Config dialog ─────────────────────────────────────────────────────────────
class ConfigForm : Form {
    private TextBox  txtFolder;
    private TextBox  txtSlideInterval;
    private TextBox  txtFadeDuration;
    private Button   btnBrowse, btnOk, btnCancel;
    private Label    lblFolder, lblSlideInterval, lblFadeDuration;

    public ConfigForm() {
        Text            = "Lenex Slideshow Screensaver - Settings";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition   = FormStartPosition.CenterScreen;
        ClientSize      = new Size(480, 175);
        MaximizeBox     = MinimizeBox = false;

        // Photo folder row
        lblFolder        = new Label  { Text = "Photo folder:",        Left = 10,  Top = 15,  Width = 115, Height = 20 };
        txtFolder        = new TextBox{ Left = 130, Top = 12,  Width = 250, Height = 22, Text = Settings.PhotoFolder };
        btnBrowse        = new Button { Text = "...",                  Left = 385, Top = 11,  Width = 30,  Height = 24 };

        // Slide interval row
        lblSlideInterval = new Label  { Text = "Slide interval (ms):", Left = 10,  Top = 50,  Width = 115, Height = 20 };
        txtSlideInterval = new TextBox{ Left = 130, Top = 47, Width = 100, Height = 22,
                                        Text = Settings.SlideIntervalMs.ToString() };

        // Fade duration row
        lblFadeDuration  = new Label  { Text = "Fade duration (ms):",  Left = 10,  Top = 85,  Width = 115, Height = 20 };
        txtFadeDuration  = new TextBox{ Left = 130, Top = 82, Width = 100, Height = 22,
                                        Text = Settings.FadeDurationMs.ToString() };

        // Buttons
        btnOk     = new Button { Text = "OK",     Left = 295, Top = 135, Width = 80, Height = 28, DialogResult = DialogResult.OK };
        btnCancel = new Button { Text = "Cancel", Left = 385, Top = 135, Width = 80, Height = 28, DialogResult = DialogResult.Cancel };

        btnBrowse.Click += (s, e) => {
            using (var dlg = new FolderBrowserDialog { SelectedPath = txtFolder.Text })
                if (dlg.ShowDialog() == DialogResult.OK) txtFolder.Text = dlg.SelectedPath;
        };

        btnOk.Click += (s, e) => {
            Settings.PhotoFolder = txtFolder.Text;

            // Persist SlideIntervalMs to registry if valid
            int slideMs;
            if (int.TryParse(txtSlideInterval.Text, out slideMs) && slideMs >= 1000)
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Lenex\Screenlock"))
                    k.SetValue("SlideIntervalMs", slideMs, RegistryValueKind.DWord);

            // Persist FadeDurationMs to registry if valid
            int fadeMs;
            if (int.TryParse(txtFadeDuration.Text, out fadeMs) && fadeMs >= 0)
                using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Lenex\Screenlock"))
                    k.SetValue("FadeDurationMs", fadeMs, RegistryValueKind.DWord);

            Close();
        };

        Controls.AddRange(new Control[] {
            lblFolder, txtFolder, btnBrowse,
            lblSlideInterval, txtSlideInterval,
            lblFadeDuration,  txtFadeDuration,
            btnOk, btnCancel
        });
        AcceptButton = btnOk;
        CancelButton = btnCancel;
    }
}

// ── Per-monitor slideshow form ────────────────────────────────────────────────
class SlideshowForm : Form {
    private readonly List<string> _images;
    private readonly object       _lock  = new object();
    private int                   _index = 0;
    private readonly Rectangle    _screenBounds;

    // Fade state
    private Bitmap _current;
    private Bitmap _next;
    private float  _fadeAlpha = 1f;
    private bool   _fading    = false;

    // Timers
    private readonly Timer _slideTimer;
    private readonly Timer _fadeTimer;

    // Mouse exit detection
    private Point _startMousePos;
    private bool  _firstMove = true;

    // Preview mode
    private readonly bool _preview;

    // Static close-all coordination
    public static event EventHandler CloseAll;

    public SlideshowForm(List<string> images, int startIndex, Screen screen, bool preview, IntPtr previewHandle) {
        _images       = images;
        _index        = startIndex;
        _preview      = preview;
        _screenBounds = screen.Bounds;

        FormBorderStyle = FormBorderStyle.None;
        BackColor       = Color.Black;
        TopMost         = true;
        Cursor          = Cursors.Default;
        DoubleBuffered  = true;
        ShowInTaskbar   = false;

        if (preview) {
            // Embed into screensaver settings preview window
            NativeMethods.RECT rc;
            NativeMethods.GetClientRect(previewHandle, out rc);
            Bounds = new Rectangle(0, 0, rc.Right - rc.Left, rc.Bottom - rc.Top);
            NativeMethods.SetParent(Handle, previewHandle);
            NativeMethods.SetWindowLong(Handle, NativeMethods.GWL_STYLE,
                NativeMethods.GetWindowLong(Handle, NativeMethods.GWL_STYLE) | NativeMethods.WS_CHILD);
        } else {
            // Force handle creation before positioning so Windows places the window
            // correctly on the target screen, including negative-coordinate screens
            CreateHandle();

            // Use SetWindowPos directly — more reliable than Bounds across mixed-DPI
            // multi-monitor setups, including screens with negative X/Y coordinates
            NativeMethods.SetWindowPos(
                Handle,
                new IntPtr(-1),         // HWND_TOPMOST
                _screenBounds.X,
                _screenBounds.Y,
                _screenBounds.Width,
                _screenBounds.Height,
                NativeMethods.SWP_SHOWWINDOW
            );
        }

        SlideshowForm.CloseAll += (s, e) => SafeClose();

        // Load first image using known screen bounds as target size
        _current   = LoadImage(_index, _screenBounds.Size);
        _fadeAlpha = 1f;

        _slideTimer = new Timer { Interval = Settings.SlideIntervalMs };
        _slideTimer.Tick += (s, e) => { _slideTimer.Stop(); AdvanceImage(); };
        _slideTimer.Start();

        _fadeTimer = new Timer { Interval = 50 };
        _fadeTimer.Tick += OnFadeTick;
    }

    // Scale image to the given target size — letterboxed, black bars on aspect ratio mismatch
    private Bitmap LoadImage(int idx, Size targetSize) {
        if (_images.Count == 0) return null;
        idx = ((idx % _images.Count) + _images.Count) % _images.Count;
        try {
            using (var raw = Image.FromFile(_images[idx]))
                return ScaleImage(raw, targetSize);
        } catch { return null; }
    }

    private static Bitmap ScaleImage(Image src, Size target) {
        float scaleX = (float)target.Width  / src.Width;
        float scaleY = (float)target.Height / src.Height;
        float scale  = Math.Min(scaleX, scaleY);   // letterbox: fit inside, preserve aspect ratio
        int   w      = (int)(src.Width  * scale);
        int   h      = (int)(src.Height * scale);
        int   x      = (target.Width  - w) / 2;
        int   y      = (target.Height - h) / 2;

        var bmp = new Bitmap(target.Width, target.Height, PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bmp)) {
            g.Clear(Color.Black);
            g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            g.SmoothingMode     = System.Drawing.Drawing2D.SmoothingMode.HighQuality;
            g.PixelOffsetMode   = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;
            g.DrawImage(src, x, y, w, h);
        }
        return bmp;
    }

    private void AdvanceImage() {
        lock (_lock) {
            _index = (_index + 1) % _images.Count;
            _next  = LoadImage(_index, _screenBounds.Size);
        }
        _fadeAlpha = 0f;
        _fading    = true;

        int fadeDuration = Settings.FadeDurationMs;
        if (fadeDuration <= 0) {
            // No fade configured — instant switch, skip fade timer entirely
            if (_current != null) { _current.Dispose(); }
            _current   = _next;
            _next      = null;
            _fading    = false;
            _fadeAlpha = 1f;
            Invalidate();
            _slideTimer.Start();
        } else {
            _fadeTimer.Start();
        }
    }

    private void OnFadeTick(object sender, EventArgs e) {
        int   fadeDuration = Settings.FadeDurationMs;
        float step         = (float)_fadeTimer.Interval / fadeDuration;
        _fadeAlpha         = Math.Min(1f, _fadeAlpha + step);
        Invalidate();

        if (_fadeAlpha >= 1f) {
            _fadeTimer.Stop();
            _fading = false;
            if (_current != null) { _current.Dispose(); }
            _current   = _next;
            _next      = null;
            _fadeAlpha = 1f;
            _slideTimer.Start();
        }
    }

    protected override void OnPaint(PaintEventArgs e) {
        var g = e.Graphics;
        g.Clear(Color.Black);

        if (_fading && _current != null && _next != null) {
            DrawWithOpacity(g, _current, 1f - _fadeAlpha);
            DrawWithOpacity(g, _next,    _fadeAlpha);
        } else if (_current != null) {
            g.DrawImage(_current, 0, 0);
        }
    }

    private static void DrawWithOpacity(Graphics g, Bitmap bmp, float alpha) {
        if (bmp == null || alpha <= 0f) return;
        alpha        = Math.Max(0f, Math.Min(1f, alpha));
        var cm       = new ColorMatrix();
        cm.Matrix33  = alpha;
        var ia       = new ImageAttributes();
        ia.SetColorMatrix(cm, ColorMatrixFlag.Default, ColorAdjustType.Bitmap);
        var rc       = new Rectangle(0, 0, bmp.Width, bmp.Height);
        g.DrawImage(bmp, rc, 0, 0, bmp.Width, bmp.Height, GraphicsUnit.Pixel, ia);
    }

    // ── Input handling — any movement/keypress/click exits all forms ─────────
    protected override void OnMouseMove(MouseEventArgs e) {
        if (_preview) return;
        if (_firstMove) { _startMousePos = e.Location; _firstMove = false; return; }
        if (Math.Abs(e.X - _startMousePos.X) > 5 || Math.Abs(e.Y - _startMousePos.Y) > 5)
            CloseAll(this, EventArgs.Empty);
    }
    protected override void OnMouseDown(MouseEventArgs e) { if (!_preview) CloseAll(this, EventArgs.Empty); }
    protected override void OnKeyDown(KeyEventArgs e)     { if (!_preview) CloseAll(this, EventArgs.Empty); }

    private void SafeClose() {
        if (InvokeRequired) { Invoke(new Action(SafeClose)); return; }
        _slideTimer.Stop();
        _fadeTimer.Stop();
        Close();
    }

    protected override void Dispose(bool disposing) {
        if (disposing) {
            _slideTimer.Dispose();
            _fadeTimer.Dispose();
            if (_current != null) { _current.Dispose(); }
            if (_next    != null) { _next.Dispose();    }
        }
        base.Dispose(disposing);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────
static class Program {
    [STAThread]
    static void Main(string[] args) {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        string arg = args.Length > 0 ? args[0].ToLower().TrimStart('-', '/') : "c";

        if (arg == "c" || arg == "config") {
            Application.Run(new ConfigForm());
            return;
        }

        if (arg == "p" && args.Length > 1) {
            // Preview mode — single form embedded in screensaver settings preview window
            long hwndLong;
            if (!long.TryParse(args[1], out hwndLong)) return;
            IntPtr hwnd = new IntPtr(hwndLong);
            var images  = GetImages();
            var form    = new SlideshowForm(images, 0, Screen.PrimaryScreen, true, hwnd);
            Application.Run(form);
            return;
        }

        if (arg == "s") {
            // Screensaver mode — one borderless form per connected monitor, each on its own STA thread
            NativeMethods.ShowCursor(false);
            var images = GetImages();
            if (images.Count == 0) { Application.Exit(); return; }

            // Shuffle image list so order is random each run
            var rng = new Random();
            images = images.OrderBy(x => rng.Next()).ToList();

            var screens = Screen.AllScreens;
            var threads = new System.Threading.Thread[screens.Length];

            for (int i = 0; i < screens.Length; i++) {
                int startIdx        = (i * Math.Max(1, images.Count / screens.Length)) % images.Count;
                Screen screen       = screens[i];
                List<string> imgs   = new List<string>(images);
                int idx             = startIdx;

                var t = new System.Threading.Thread(() => {
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    var form = new SlideshowForm(imgs, idx, screen, false, IntPtr.Zero);
                    Application.Run(form);
                });

                t.SetApartmentState(System.Threading.ApartmentState.STA);
                t.IsBackground = true;
                threads[i] = t;
            }

            // Start all monitor threads simultaneously
            foreach (var t in threads) t.Start();

            // Wait for all threads to finish before restoring cursor
            foreach (var t in threads) t.Join();

            NativeMethods.ShowCursor(true);
            return;
        }

        // Fallback: show config dialog
        Application.Run(new ConfigForm());
    }

    private static List<string> GetImages() {
        var folder = Settings.PhotoFolder;
        if (!Directory.Exists(folder)) return new List<string>();
        var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".jpg", ".jpeg", ".png", ".bmp", ".gif" };
        return Directory.GetFiles(folder, "*.*", SearchOption.TopDirectoryOnly)
                        .Where(f => exts.Contains(Path.GetExtension(f)))
                        .ToList();
    }
}
"@
#endregion

#region ── Substitute placeholders ──────────────────────────────────────────────
Write-Log "Substituting build-time values into C# source..." INFO

# Default slide interval: 10 seconds (10000 ms)
$DefaultSlideIntervalMs = 10000
# Default fade duration: 0 ms (instant, no crossfade)
$DefaultFadeDurationMs  = 0

$CSharpSource = $CSharpSource `
    -replace '%%PHOTO_FOLDER%%',      ($PhotoFolder -replace '\\', '\\') `
    -replace '%%SLIDE_INTERVAL_MS%%', $DefaultSlideIntervalMs `
    -replace '%%FADE_DURATION_MS%%',  $DefaultFadeDurationMs
#endregion

#region ── Compile via Windows PowerShell 5.1 ────────────────────────────────────
$OutputExe = Join-Path $env:TEMP 'MultiMonitorSlideshow_build.exe'
$OutputScr = Join-Path "$env:SystemRoot\System32" $OutputName

Write-Log "Compiling C# source via Windows PowerShell 5.1 to: $OutputExe" INFO

# Write C# source to a temp file so we can pass it cleanly to the child process
$CSharpFile = Join-Path $env:TEMP 'MultiMonitorSlideshow_build.cs'
$CSharpSource | Set-Content -Path $CSharpFile -Encoding UTF8

# Build compile script for the WPS 5.1 child process
$CompileScript = @"
`$compilerParams = New-Object System.CodeDom.Compiler.CompilerParameters
`$compilerParams.GenerateExecutable      = `$true
`$compilerParams.OutputAssembly          = '$OutputExe'
`$compilerParams.CompilerOptions         = '/target:winexe /optimize+ /platform:x64 /langversion:5'
`$compilerParams.ReferencedAssemblies.AddRange(@(
    'System.dll',
    'System.Core.dll',
    'System.Drawing.dll',
    'System.Windows.Forms.dll'
))
`$source   = [System.IO.File]::ReadAllText('$CSharpFile')
`$provider = New-Object Microsoft.CSharp.CSharpCodeProvider
`$result   = `$provider.CompileAssemblyFromSource(`$compilerParams, `$source)
`$errors   = @(`$result.Errors | Where-Object { -not `$_.IsWarning })
if (`$errors.Count -gt 0) {
    foreach (`$e in `$errors) { Write-Host "ERROR|`$(`$e.Line)|`$(`$e.ErrorText)" }
} else {
    Write-Host 'SUCCESS'
}
"@

$CompileScriptFile = Join-Path $env:TEMP 'MultiMonitorSlideshow_compile.ps1'
$CompileScript | Set-Content -Path $CompileScriptFile -Encoding UTF8

# Run compile script in Windows PowerShell 5.1
$ps5 = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path $ps5)) {
    Write-Log "Windows PowerShell 5.1 not found at: $ps5" ERROR
    return
}

$output = & $ps5 -NoProfile -ExecutionPolicy Bypass -File $CompileScriptFile

# Parse output from child process
$compileErrors  = @($output | Where-Object { $_ -like 'ERROR|*' })
$compileSuccess = @($output | Where-Object { $_ -eq 'SUCCESS' })

foreach ($err in $compileErrors) {
    $parts = $err -split '\|', 3
    Write-Log "  [Line $($parts[1])] $($parts[2])" ERROR
}

if ($compileErrors.Count -gt 0) {
    Write-Log "Compilation failed with $($compileErrors.Count) error(s)." ERROR
    return
}

if ($compileSuccess.Count -eq 0) {
    Write-Log "Compilation produced no output — unknown failure." ERROR
    Write-Log "Child process output: $($output -join '; ')" ERROR
    return
}

Write-Log "Compilation succeeded: $OutputExe" SUCCESS
#endregion

#region ── Deploy to System32 ────────────────────────────────────────────────────
Write-Log "Copying screensaver to: $OutputScr" INFO

if (-not (Test-Path $OutputExe)) {
    Write-Log "Build output not found at '$OutputExe' — aborting deploy." ERROR
    return
}

try {
    Copy-Item -Path $OutputExe -Destination $OutputScr -Force
    Write-Log "Deployed successfully: $OutputScr" SUCCESS
} catch {
    Write-Log "Failed to copy to System32: $_" ERROR
    return
}
#endregion

Write-Log "Done. '$OutputName' is ready in System32." SUCCESS
Write-Log "SCRNSAVE.EXE registration is managed by the Screenlock v1.4 script." INFO
Write-Log "Log written to: $LogFile" INFO
