<#
.SYNOPSIS
    資深系統整合工程師實作版本 - Print Server HTTP API & Proactive Monitor
    版本：v17.9 (Data Timestamp Update)
    修正：
    1. 新增 API 回傳欄位 "LastUpdated"：在每一筆印表機資料中加入伺服器端的產生時間戳記。
    2. 維持 v17.8 的所有功能：RawUrl 解析、Zero-Ping、防火牆自動開通、重啟保護、CORS、自癒。

.DESCRIPTION
    本腳本具備多層次自我檢查與自動修復機制 (Self-Healing & Resilience)：
    1. [列印作業自癒] 清除殭屍作業 (狀態 Error/Deleting)
    2. [列印服務自癒] 偵測堵塞 ($queueThreshold) 並重啟 Spooler
    3. [系統健康維護] 排程環境重置 (Cron: $scheduledHealCron)
    4. [腳本韌性] 啟動重試、防火牆開通、通知防卡死 (TCP Check)
    5. [資安合規] Zero-Ping (使用 TCP 9100/80 偵測)

.NOTES
    ?? 測試指令
    curl -H "X-API-KEY: %API_KEY%" http://%SERVER_IP%:8888/printers
#>

# -------------------------------------------------------------------------
# 1. 基礎設定區
# -------------------------------------------------------------------------
$port               = 8888
$apiKey             = "YourSecretApiKey123"      
$logPath            = "C:\Temp"
$uploadPath         = "C:\Temp\Uploads"           
$maxLogSizeBytes    = 10MB                       
$maxHistory         = 5                          
$logRetentionDays   = 7                   

# --- PDF 閱讀器路徑 ---
$pdfReaderPaths     = @(
    "C:\Program Files (x86)\Foxit Software\Foxit PDF Reader\FoxitPDFReader.exe",
    "C:\Program Files\Foxit Software\Foxit PDF Reader\FoxitPDFReader.exe",
    "C:\FoxitReader\Foxit Reader.exe",
    "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
    "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
)

# --- 通知伺服器設定 ---
$notifyIp           = "220.1.34.75"
$notifyPort         = 80
$notifyEndpoint     = "/api/notification_json_api.php"
$notifyUrl          = "http://$notifyIp$notifyEndpoint"
$notifyChannels     = @("HA10013859")

# [設定] 通知伺服器健康檢查
$enableNotifyHealthCheck = $true
$notifyTimeoutMs         = 1000

# [設定] Admin 通知開關
$enableAdminNotifications = $false    

# --- 監控設定 ---
$checkIntervalSec   = 60                  
$errorThreshold     = 5                   
$monitorStartHour   = 8
$monitorEndHour     = 17
$monitorDays        = @("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")

# --- 自癒設定 ---
$enableAutoCleanup  = $true               
$zombieTimeMinutes  = 10                  
$enableAutoHeal     = $true               
$maxStuckPrinters   = 3                   
$enableScheduledHeal = $true
$scheduledHealCron   = "30 7 * * *"       
$queueThreshold     = 20                  
$queueStuckLimit    = 5                   

# --- 排除設定 ---
$excludeKeywords    = @("PDF", "XPS", "Fax", "OneNote", "Microsoft Shared Fax")
$manualExcludePrinters = @(
    "範例印表機名稱_A",
    "範例印表機名稱_B"
)

# 全局狀態變數
$global:PrinterStateCache   = New-Object System.Collections.Hashtable
$global:PrinterErrorCount   = New-Object System.Collections.Hashtable 
$global:ExcludedPrinters    = New-Object System.Collections.Hashtable 
$global:QueueStuckCount     = New-Object System.Collections.Hashtable 
$global:LastQueueCount      = New-Object System.Collections.Hashtable 
$global:IsFirstRun          = $true
$global:ValidPdfReader      = $null
$global:LastCronRunTime     = $null 
$global:IsNotifyServerOnline = $true 
$restartScript = $false
$restartComputer = $false

# -------------------------------------------------------------------------
# 2. 核心函數庫
# -------------------------------------------------------------------------

function ConvertTo-SimpleJson {
    param($InputObject)
    if ($null -eq $InputObject) { return "null" }
    if ($InputObject -is [string]) { return """$($InputObject.Replace('\', '\\').Replace('"', '\"'))""" }
    if ($InputObject -is [System.Boolean]) { if ($InputObject) { return "true" } else { return "false" } }
    if ($InputObject -is [System.ValueType]) { return $InputObject.ToString().ToLower() }
    
    $type = $InputObject.GetType()
    if ($null -ne $type.GetInterface("IDictionary")) {
        $pairs = New-Object System.Collections.Generic.List[string]
        foreach ($key in $InputObject.Keys) { $pairs.Add("""$key"":" + (ConvertTo-SimpleJson $InputObject[$key])) }
        return "{" + [string]::Join(",", $pairs) + "}"
    }
    if ($null -ne $type.GetInterface("IEnumerable")) {
        $elements = New-Object System.Collections.Generic.List[string]
        foreach ($item in $InputObject) { $elements.Add((ConvertTo-SimpleJson $item)) }
        return "[" + [string]::Join(",", $elements) + "]"
    }
    
    $objPairs = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($prop in $InputObject.PSObject.Properties) { $objPairs.Add("""$($prop.Name)"":" + (ConvertTo-SimpleJson $prop.Value)) }
    } catch { return """$($InputObject.ToString())""" }
    
    if ($objPairs.Count -gt 0) { return "{" + [string]::Join(",", $objPairs) + "}" } else { return """$($InputObject.ToString())""" }
}

function Write-ApiLog {
    param([string]$message, [ConsoleColor]$Color = "Gray")
    try {
        if (-not (Test-Path $logPath)) { [void](New-Item -ItemType Directory -Path $logPath -Force) }
        $today = Get-Date -Format "yyyy-MM-dd"
        $fullPath = Join-Path $logPath "PrintApi_$today.log"
        $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $message"
        if (Test-Path $fullPath) {
            if ((Get-Item $fullPath).Length -ge $maxLogSizeBytes) {
                if (Test-Path "$fullPath.$maxHistory") { Remove-Item "$fullPath.$maxHistory" -Force }
                for ($i = $maxHistory - 1; $i -ge 1; $i--) { $src = "$fullPath.$i"; $dest = "$fullPath.$($i + 1)"; if (Test-Path $src) { Move-Item $src $dest -Force } }
                Move-Item $fullPath "$fullPath.1" -Force
            }
        }
        Add-Content -Path $fullPath -Value $logEntry
        if ($Color -ne "Gray") { Write-Host $logEntry -ForegroundColor $Color } else { Write-Host $logEntry }
    } catch {}
}

function Cleanup-OldLogs {
    try {
        if (Test-Path $logPath) {
            $limitDate = (Get-Date).AddDays(-$logRetentionDays)
            $oldFiles = Get-ChildItem -Path $logPath -Filter "PrintApi_*.log*" | Where-Object { $_.LastWriteTime -lt $limitDate }
            if ($null -ne $oldFiles) { foreach ($file in $oldFiles) { Remove-Item $file.FullName -Force } }
        }
    } catch {}
}

function Setup-FirewallRule {
    param([int]$targetPort)
    Write-ApiLog "正在檢查防火牆規則 Port $targetPort..." -Color Yellow
    try {
        $ruleName = "PrintApiServer_Port_$targetPort"
        $check = netsh advfirewall firewall show rule name="$ruleName" 2>&1
        if ($check -match "No rules match") {
            Write-ApiLog ">>> 防火牆規則不存在，正在建立..." -Color Cyan
            netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=TCP localport=$targetPort
            Write-ApiLog "[系統初始化] 已自動建立防火牆規則: $ruleName"
        } else { Write-ApiLog ">>> 防火牆規則已存在。" -Color Green }
    } catch { Write-ApiLog "!!! [防火牆設定失敗] 請手動執行 netsh" -Color Red }
}

function Test-TcpConnection {
    param([string]$target, [int]$port, [int]$timeoutMs)
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $tcp.BeginConnect($target, $port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($timeoutMs, $false)) { $tcp.EndConnect($async); return $true }
        return $false
    } catch { return $false } finally { if ($tcp.Connected) { $tcp.Close() } else { $tcp.Close() } }
}

function Send-SysAdminNotify {
    param([string]$content, [string]$title = "印表機系統通知")
    if ($null -eq $notifyChannels -or $notifyChannels.Count -eq 0) { return }
    if ($enableNotifyHealthCheck -and (-not $global:IsNotifyServerOnline)) { return }

    try {
        $localIp = "127.0.0.1"
        try { $ipConfig = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }; if ($null -ne $ipConfig) { if ($ipConfig -is [array]) { $localIp = $ipConfig[0].IPAddress[0] } else { $localIp = $ipConfig.IPAddress[0] } } } catch { }
        $fields = @{ "type"="add_notification"; "title"=$title; "content"=$content; "priority"="3"; "sender"="$($env:COMPUTERNAME) ($localIp)"; "from_ip"=$localIp }
        $encodedParts = New-Object System.Collections.Generic.List[string]
        foreach ($key in $fields.Keys) { $encodedParts.Add("$key=$([System.Uri]::EscapeDataString($fields[$key]))") }
        if ($null -ne $notifyChannels) { foreach ($chan in $notifyChannels) { $encodedParts.Add("channels[]=$([System.Uri]::EscapeDataString($chan))") } }
        $postBody = [string]::Join("&", $encodedParts)
        
        $req = [System.Net.WebRequest]::Create($notifyUrl); $req.Method = "POST"; $req.ContentType = "application/x-www-form-urlencoded"; $req.Timeout = 1000 
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($postBody); $req.ContentLength = $bytes.Length
        $reqStream = $req.GetRequestStream(); $reqStream.Write($bytes, 0, $bytes.Length); $reqStream.Close()
        $resp = $req.GetResponse(); $resp.Close()
    } catch { Write-ApiLog "!!! [通知失敗] $($_.Exception.Message)" }
}

function Invoke-SpoolerSelfHealing {
    param([string]$reason)
    Write-ApiLog "!!! [自癒啟動] $reason"
    Send-SysAdminNotify -title "?? 自癒啟動" -content "偵測到異常 ($reason)，正在執行修復。"
    try {
        Stop-Service "Spooler" -Force; Start-Sleep -Seconds 3
        if (Test-Path "C:\Windows\System32\spool\PRINTERS") { Get-ChildItem -Path "C:\Windows\System32\spool\PRINTERS\*" -Include *.* -Force | Remove-Item -Force }
        Start-Service "Spooler"
        Send-SysAdminNotify -title "? 自癒完成" -content "服務已重啟。"
    } catch { Send-SysAdminNotify -title "? 自癒失敗" -content "錯誤: $($_.Exception.Message)" }
}

function Test-CronMatch {
    param($cron, $now)
    if ([string]::IsNullOrEmpty($cron)) { return $false }
    $parts = $cron.Split(" "); if ($parts.Count -ne 5) { return $false }
    $min=$parts[0]; $hour=$parts[1]; $dom=$parts[2]; $month=$parts[3]; $dow=$parts[4]
    function Check($p, $v) {
        if ($p -eq "*") { return $true }
        if ($p -match "^(\*|\d+)/(\d+)$") { return ($v % [int]$matches[2]) -eq 0 }
        if ($p -match ",") { foreach($i in $p.Split(",")){ if([int]$i -eq $v){return $true} }; return $false }
        return [int]$p -eq $v
    }
    return (Check $min $now.Minute) -and (Check $hour $now.Hour) -and (Check $dom $now.Day) -and (Check $month $now.Month) -and (Check $dow [int]$now.DayOfWeek)
}

function Get-Utf8QueryParam { param($r, $k); if ($r.Url.Query -match "[?&]$k=([^&]*)") { return [System.Uri]::UnescapeDataString($matches[1]) }; return $null }

function Get-PrinterStatusData {
    $results = New-Object System.Collections.Generic.List[Object]
    $portMap = @{}
    
    # [新增] 取得目前伺服器時間
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    try { $tcpPorts = Get-WmiObject -Class Win32_TCPIPPrinterPort -ErrorAction SilentlyContinue; if($tcpPorts){ foreach($t in $tcpPorts){ if($t.Name){$portMap[$t.Name]=$t.HostAddress} } } } catch {}
    $wmiPrinters = Get-WmiObject -Class Win32_Printer

    foreach ($p in $wmiPrinters) {
        $pName = $p.Name; $shouldSkip = $false
        foreach ($kw in $excludeKeywords) { if ($pName -like "*$kw*") { $shouldSkip=$true; break } }
        if ($shouldSkip) { continue }
        foreach ($exName in $manualExcludePrinters) { if ($pName -eq $exName) { $shouldSkip=$true; break } }
        if ($shouldSkip) { continue }

        $errDetails = ""; $finalStatus = "Ready"
        if ($p.WorkOffline) { $finalStatus = "Offline" }
        elseif ($p.DetectedErrorState -ne 0) { $finalStatus = "Error"; $errDetails = "硬體偵測錯誤代碼: $($p.DetectedErrorState)" }
        else {
            switch ($p.PrinterStatus) {
                1 { $finalStatus = "Error"; $errDetails = "未知 - 驅動/SNMP異常" }
                2 { $finalStatus = "Error"; $errDetails = "其他錯誤" }
                4 { $finalStatus = "Printing" } 5 { $finalStatus = "Warmup" }
                default { $finalStatus = "Ready"; if($p.PrinterStatus -ne 3){$finalStatus="Warning"} }
            }
        }
        
        $pIP = if ($portMap.ContainsKey($p.PortName)) { $portMap[$p.PortName] } else { $p.PortName }
        if ($pIP -match "^\d+\.\d+\.\d+\.\d+$") {
            if (-not (Test-TcpConnection $pIP 9100 200)) {
                if ($finalStatus -eq "Offline") { $errDetails = "無回應 (TCP/9100)" }
                elseif ($finalStatus -like "Ready*") { $finalStatus = "Warning"; $errDetails = "無回應 - 可能斷線" }
            } else {
                if ($finalStatus -eq "Offline") { $errDetails = "軟體離線 - 網路通暢" }
            }
        }

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name $pName
        $obj | Add-Member NoteProperty Status $finalStatus
        $obj | Add-Member NoteProperty Jobs ($p.JobCount -as [int])
        $obj | Add-Member NoteProperty IP $pIP
        $obj | Add-Member NoteProperty Location ($p.Location -as [string])
        $obj | Add-Member NoteProperty Comment ($p.Comment -as [string])
        $obj | Add-Member NoteProperty Driver ($p.DriverName -as [string])
        $obj | Add-Member NoteProperty PortName $p.PortName
        $obj | Add-Member NoteProperty ShareName ($p.ShareName -as [string])
        $obj | Add-Member NoteProperty ErrorDetails $errDetails 
        $obj | Add-Member NoteProperty LastUpdated $timestamp # [新增] 加入時間戳
        $results.Add($obj)
    }
    return $results
}

function Test-PrinterHealth {
    Cleanup-OldLogs
    $printers = Get-PrinterStatusData
    $batchAlerts = New-Object System.Collections.Generic.List[string]
    $stuck = 0
    
    if ($enableAutoCleanup) {
        $zombies = Get-WmiObject Win32_PrintJob | Where-Object { $_.JobStatus -like "*Error*" -or $_.JobStatus -like "*Deleting*" }
        if ($zombies) { foreach($z in $zombies){ $batchAlerts.Add("自癒清理: $($z.JobId)"); $z.Delete() } }
    }

    foreach ($p in $printers) {
        $n = $p.Name; $s = $p.Status; $j = $p.Jobs
        if ($global:IsFirstRun) { if($s -like "Offline*"){$global:ExcludedPrinters[$n]=$true}; $global:LastQueueCount[$n]=$j; continue }
        if ($global:ExcludedPrinters.ContainsKey($n)) { if($s -eq "Ready" -or $s -eq "Printing"){$global:ExcludedPrinters.Remove($n)}; continue }
        
        if ($s -eq "Error" -or $s -eq "Warning") {
            $global:PrinterErrorCount[$n]++
            if ($global:PrinterErrorCount[$n] -eq $errorThreshold) { 
                $msg = "● [異常] $n $s"; if($p.ErrorDetails){$msg+=" ($($p.ErrorDetails))"}; $batchAlerts.Add($msg) 
            }
        } else {
            if ($global:PrinterErrorCount[$n] -ge $errorThreshold) { $batchAlerts.Add("○ [恢復] $n") }
            $global:PrinterErrorCount[$n] = 0
        }
        if ($j -ge $queueThreshold -and $j -ge $global:LastQueueCount[$n]) {
            $global:QueueStuckCount[$n]++
            if ($global:QueueStuckCount[$n] -eq $queueStuckLimit) { $batchAlerts.Add("?? [堵塞] $n 佇列停滯"); $stuck++ }
        } else { $global:QueueStuckCount[$n] = 0 }
        $global:LastQueueCount[$n] = $j
    }

    if ($enableAutoHeal -and $stuck -ge $maxStuckPrinters) { Invoke-SpoolerSelfHealing -reason "多台堵塞" }
    if ($global:IsFirstRun) { $global:IsFirstRun = $false; return }
    if ($batchAlerts.Count -gt 0 -and $enableAdminNotifications) { Send-SysAdminNotify -content ([string]::Join("`n", $batchAlerts)) -title "印表機告警" }
}

# -------------------------------------------------------------------------
# 3. 主程序 (HttpListener)
# -------------------------------------------------------------------------
Write-ApiLog "----------------------------------------" -Color Cyan
Write-ApiLog " Print Server API & Monitor v17.9 " -Color Cyan
Write-ApiLog "----------------------------------------" -Color Cyan

# A. 防火牆設定
Setup-FirewallRule $port

# B. PDF 閱讀器偵測
foreach ($path in $pdfReaderPaths) { if (Test-Path $path) { $global:ValidPdfReader = $path; break } }
if ($global:ValidPdfReader) { Write-ApiLog "PDF Reader: OK ($global:ValidPdfReader)" -Color Green }
else { Write-ApiLog "PDF Reader: Not Found (Fallback to Shell)" -Color Yellow }

# C. 通知伺服器偵測
if ($enableNotifyHealthCheck) {
    if (Test-TcpConnection $notifyIp $notifyPort $notifyTimeoutMs) { Write-ApiLog "Notify Server: OK" -Color Green }
    else { $global:IsNotifyServerOnline = $false; Write-ApiLog "Notify Server: Offline (Notifications Disabled)" -Color Red }
}

# D. 啟動 Web Server (含重試機制)
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://*:$port/")
$started = $false
$retryCount = 0

while (-not $started -and $retryCount -lt 5) {
    try {
        $listener.Start()
        $started = $true
        Write-ApiLog "--- 服務已啟動，監聽 Port $port ---"
    } catch {
        $retryCount++
        Write-ApiLog "!!! 無法綁定 Port $port (嘗試 $retryCount/5): $($_.Exception.Message)" -Color Red
        Start-Sleep -Seconds 2
    }
}

if (-not $started) {
    Write-ApiLog "`n[嚴重錯誤] 服務啟動失敗！Port $port 可能被佔用或權限不足。" -Color Red
    Write-ApiLog "請嘗試以「系統管理員身分」執行，或檢查是否有殘留的 PowerShell 程序。"
    Write-ApiLog "程式將立即終止。"
    exit
}

# E. 主迴圈
$nextCheck = Get-Date; $nextHeart = Get-Date; $contextTask = $null

while ($listener.IsListening) {
    try {
        $now = Get-Date
        if ($now -ge $nextHeart) { Write-ApiLog "[Heartbeat] 服務運作中..." -Color DarkGray; $nextHeart = $now.AddSeconds(60) } 
        
        # 監控邏輯
        if ($now -ge $nextCheck) {
            $day = $now.DayOfWeek.ToString()
            if (($now.Hour -ge $monitorStartHour) -and ($now.Hour -lt $monitorEndHour) -and ($monitorDays -contains $day)) {
                Test-PrinterHealth
            }
            $nextCheck = $now.AddSeconds($checkIntervalSec)
        }

        # Cron 排程
        if ($enableScheduledHeal) {
            if ($global:LastCronRunTime -eq $null -or ($now.Minute -ne $global:LastCronRunTime.Minute -or $now.Hour -ne $global:LastCronRunTime.Hour)) {
                if (Test-CronMatch $scheduledHealCron $now) {
                    Invoke-SpoolerSelfHealing -reason "Cron 排程"
                    $global:LastCronRunTime = $now
                }
            }
        }

        # HTTP 請求處理
        if ($null -eq $contextTask) { $contextTask = $listener.BeginGetContext($null, $null) }
        if (-not $contextTask.AsyncWaitHandle.WaitOne(1000)) { continue }

        $context = $listener.EndGetContext($contextTask); $contextTask = $null
        $req = $context.Request; $res = $context.Response; $path = $req.Url.AbsolutePath.ToLower()
        Write-ApiLog ">>> [REQ] $($req.RemoteEndPoint) $path"

        $res.AddHeader("Access-Control-Allow-Origin", "*")
        $res.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        $res.AddHeader("Access-Control-Allow-Headers", "*") 

        if ($req.HttpMethod -eq "OPTIONS") { $res.StatusCode = 200; $res.Close(); continue }

        $out = @{ "success"=$false; "message"=""; "data"=$null }
        if ($req.Headers["X-API-KEY"] -ne $apiKey) { $res.StatusCode = 401 }
        else {
            if ($path -eq "/printers") { 
                $out.data = Get-PrinterStatusData; $out.success = $true; $out.message = "OK" 
            }
            elseif ($path -eq "/server/logs") {
                $logF = Join-Path $logPath "PrintApi_$(Get-Date -Format 'yyyy-MM-dd').log"
                if (Test-Path $logF) {
                    $cnt = 100; $l = Get-Utf8QueryParam $req "lines"; if($l -match "^\d+$"){$cnt=[int]$l}
                    $out.data = Get-Content $logF | Select-Object -Last $cnt; $out.success = $true
                } else { $out.message = "No Log" }
            }
            elseif ($path -eq "/server/restart-script") {
                $out.success = $true; $out.message = "Restarting..."
                Write-ApiLog ">>> 重啟腳本指令"
                $restartScript = $true
            }
            elseif ($path -eq "/server/restart-computer") {
                $out.success = $true; $out.message = "Rebooting OS in 5s..."
                Write-ApiLog ">>> 重啟電腦指令"
                $restartComputer = $true
            }
            elseif ($path -eq "/printer/update") {
                $n=Get-Utf8QueryParam $req "name"; $l=Get-Utf8QueryParam $req "location"; $c=Get-Utf8QueryParam $req "comment"
                # [新增] 除錯日誌
                Write-ApiLog ">>> [DEBUG] Update: Name='$n', Loc='$l', Com='$c'"
                
                $p=Get-WmiObject Win32_Printer|Where{$_.Name -eq $n}
                if($p){
                    if($l){$p.Location=$l}; if($c){$p.Comment=$c}
                    try{$p.Put(); $out.success=$true; $out.message="Updated"}catch{$out.message=$_.Exception.Message}
                } else { $out.message = "Not Found: $n" }
            }
            elseif ($path -eq "/printer/print-pdf") {
                if ($req.HttpMethod -eq "POST") {
                    $n = Get-Utf8QueryParam $req "name"
                    Write-ApiLog ">>> [DEBUG] PrintPDF: Name='$n'"
                    
                    $p = Get-WmiObject Win32_Printer | Where {$_.Name -eq $n}
                    if ($p) {
                         $dup = Get-Utf8QueryParam $req "duplex"
                         # ... (Set Duplex Logic) ...
                         if ($dup) {
                            if (Get-Command Set-PrintConfiguration -ErrorAction SilentlyContinue) {
                                try {
                                    $cfg = Get-PrintConfiguration -PrinterName $n -ErrorAction Stop
                                    $oldDup = $cfg.DuplexingMode
                                    $tDup = "OneSided"
                                    if ($dup -eq "1" -or $dup -eq "long") { $tDup = "TwoSidedLongEdge" }
                                    elseif ($dup -eq "2" -or $dup -eq "short") { $tDup = "TwoSidedShortEdge" }
                                    if ($oldDup -ne $tDup) { Set-PrintConfiguration -PrinterName $n -DuplexingMode $tDup; $restoreDup=$true }
                                } catch {}
                            }
                         }

                         $fName = "Upload_$(Get-Date -Format 'yyyyMMdd_HHmmss').pdf"
                         $fPath = Join-Path $uploadPath $fName
                         $fs = New-Object System.IO.FileStream($fPath, [System.IO.FileMode]::Create)
                         $buf = New-Object byte[] 8192
                         do { $r=$req.InputStream.Read($buf,0,$buf.Length); if($r -gt 0){$fs.Write($buf,0,$r)} } while($r -gt 0)
                         $fs.Close()

                         try {
                             if ($global:ValidPdfReader) {
                                 Start-Process -FilePath $global:ValidPdfReader -ArgumentList "/t `"$fPath`" `"$n`"" -WindowStyle Hidden
                             } else {
                                 Start-Process -FilePath $fPath -Verb PrintTo -ArgumentList "`"$n`"" -WindowStyle Hidden
                             }
                             $out.success=$true
                         } catch { $out.message=$_.Exception.Message }

                         if ($restoreDup) { try{ Set-PrintConfiguration -PrinterName $n -DuplexingMode $oldDup }catch{} }
                    } else { $out.message = "Not Found: $n" }
                }
            }
            elseif ($path -eq "/printer/status") {
                $n = Get-Utf8QueryParam $req "name"
                Write-ApiLog ">>> [DEBUG] Status: Name='$n'"
                $data = Get-PrinterStatusData
                foreach($item in $data){if($item.Name -eq $n){$out.data=$item; $out.success=$true; break}}
            }
            elseif ($path -eq "/printer/refresh") {
                $n = Get-Utf8QueryParam $req "name"
                Write-ApiLog ">>> [DEBUG] Refresh: Name='$n'"
                $p = Get-WmiObject Win32_Printer | Where {$_.Name -eq $n}
                if($p){ $p.Pause(); Start-Sleep -m 500; $p.Resume(); $out.success=$true }
            }
            elseif ($path -eq "/printer/clear") {
                $n = Get-Utf8QueryParam $req "name"
                Write-ApiLog ">>> [DEBUG] Clear: Name='$n'"
                $js = Get-WmiObject Win32_PrintJob | Where {$_.Name -like "*$n*"}
                if($js){ foreach($j in $js){$j.Delete()}; $out.success=$true } else { $out.success=$true } 
            }
            elseif ($path -eq "/service/restart-spooler") {
                try { Restart-Service "Spooler" -Force; $out.success=$true } catch { $out.message=$_.Exception.Message }
            }
            elseif ($path -eq "/service/self-heal") {
                Invoke-SpoolerSelfHealing -reason "API Trigger"; $out.success=$true
            }
            else { $res.StatusCode = 404 }
        }

        $json = ConvertTo-SimpleJson $out
        $buf = [System.Text.Encoding]::UTF8.GetBytes($json)
        $res.ContentType = "application/json"
        try {
            $res.ContentLength64 = $buf.Length
            $res.OutputStream.Write($buf, 0, $buf.Length)
            $res.Close()
        } catch { Write-ApiLog ">>> [Warn] Client disconnected early" }

        if ($restartScript) {
            Write-ApiLog ">>> 重啟中..."
            try { $listener.Stop(); $listener.Close() } catch {}
            Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`"" -WindowStyle Hidden
            exit
        }
        if ($restartComputer) {
            Write-ApiLog ">>> 關機中..."
            try { $listener.Stop(); $listener.Close() } catch {}
            if ($enableAdminNotifications) { Send-SysAdminNotify -content "API：收到管理員指令，伺服器即將在 5 秒後重新啟動。" -title "系統操作" }
            Start-Process "shutdown.exe" -ArgumentList "/r /t 5 /f /d p:4:1"
            exit
        }

    } catch { 
        Write-ApiLog "!!! [Error] $($_.Exception.Message)"
        $contextTask = $null 
    }
}