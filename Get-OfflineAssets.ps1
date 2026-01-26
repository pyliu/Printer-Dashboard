<#
.SYNOPSIS
    PrintMonitor 前端資源下載器 v1.1
.DESCRIPTION
    此腳本會下載 Vue, Axios, Tailwind, FontAwesome 等資源，
    並整理至 ./offline 資料夾中。
    v1.1 修正:
    1. 下載 .ttf 字型檔以提升相容性。
    2. 自動修正 CSS 內的字型路徑 (../webfonts -> webfonts)。
#>

$ErrorActionPreference = "Stop"
$destDir = "offline"

# 1. 建立目錄
if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
if (-not (Test-Path "$destDir\webfonts")) { New-Item -ItemType Directory -Path "$destDir\webfonts" -Force | Out-Null }

Write-Host ">>> 開始下載前端資源..." -ForegroundColor Cyan

# 2. 定義資源清單
$urls = @{
    "$destDir\tailwind.js" = "https://cdn.tailwindcss.com"
    "$destDir\vue.js"      = "https://unpkg.com/vue@3/dist/vue.global.js"
    "$destDir\axios.js"    = "https://unpkg.com/axios/dist/axios.min.js"
    "$destDir\toastify.js" = "https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.js"
    "$destDir\toastify.css"= "https://cdn.jsdelivr.net/npm/toastify-js/src/toastify.min.css"
    "$destDir\fontawesome.css" = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"
}

# 3. 下載核心檔案
foreach ($key in $urls.Keys) {
    $filename = $key.Split('\')[-1]
    Write-Host "下載核心: $filename ..."
    try {
        Invoke-WebRequest -Uri $urls[$key] -OutFile $key
    } catch {
        Write-Warning "下載失敗: $filename - $($_.Exception.Message)"
    }
}

# 4. 處理 FontAwesome 字型檔 (擴充支援 ttf)
$fontBaseUrl = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/webfonts"
$fonts = @(
    "fa-solid-900.woff2", "fa-solid-900.ttf",
    "fa-brands-400.woff2", "fa-brands-400.ttf",
    "fa-regular-400.woff2", "fa-regular-400.ttf",
    "fa-v4compatibility.woff2", "fa-v4compatibility.ttf"
)

foreach ($font in $fonts) {
    Write-Host "下載字型: $font ..."
    try {
        Invoke-WebRequest -Uri "$fontBaseUrl/$font" -OutFile "$destDir\webfonts\$font"
    } catch {
        Write-Warning "字型下載失敗 (可能該版本無此格式): $font"
    }
}

# 5. 合併 JS 與 CSS (製作 bundle)
Write-Host ">>> 正在合併檔案並修正路徑..." -ForegroundColor Yellow

# 合併 JS: Vue -> Axios -> Toastify
try {
    $jsContent = Get-Content "$destDir\vue.js" -Raw
    $jsContent += "`n" + (Get-Content "$destDir\axios.js" -Raw)
    $jsContent += "`n" + (Get-Content "$destDir\toastify.js" -Raw)
    Set-Content -Path "$destDir\bundle.js" -Value $jsContent -Encoding UTF8
} catch {
    Write-Error "JS 合併失敗: $($_.Exception.Message)"
}

# 合併 CSS 並修正路徑
try {
    # 讀取 FontAwesome CSS
    $faContent = Get-Content "$destDir\fontawesome.css" -Raw
    
    # [關鍵修正] 將 "../webfonts" 替換為 "webfonts"
    # 因為我們的 css 和 webfonts 資料夾是在同一層 (offline/bundle.css 和 offline/webfonts)
    $faContent = $faContent -replace '\.\./webfonts', 'webfonts'

    # 讀取 Toastify CSS
    $toastContent = Get-Content "$destDir\toastify.css" -Raw
    
    # 合併
    $finalCss = $faContent + "`n" + $toastContent
    Set-Content -Path "$destDir\bundle.css" -Value $finalCss -Encoding UTF8
} catch {
    Write-Error "CSS 合併失敗: $($_.Exception.Message)"
}

# 6. 清理暫存 (保留 tailwind.js，因為它是獨立引擎)
$tempFiles = @("vue.js", "axios.js", "toastify.js", "toastify.css", "fontawesome.css")
foreach ($file in $tempFiles) {
    Remove-Item "$destDir\$file" -ErrorAction SilentlyContinue
}

Write-Host "? 下載與修正完成！" -ForegroundColor Green
Write-Host "請重新整理瀏覽器頁面，字型錯誤應已解決。" -ForegroundColor Gray