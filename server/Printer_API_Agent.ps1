<#
.SYNOPSIS
    資深系統整合工程師實作版本 - Print Server HTTP API & Proactive Monitor
    版本：v16.9 (Admin Notification Flag Update)
    修正：
    1. 新增 $enableAdminNotifications 設定 (預設 False)：控制是否發送自動巡檢的告警通知。
    2. Test-PrinterHealth 邏輯更新：若旗標為 False，僅記錄日誌不發送外部通知。
    3. 維持 v16.8 的所有功能：API 路由修復、CORS、PDF 上傳、自癒功能。
    4. 完全相容 PowerShell 2.0 (Windows Server 2008 SP2) 至 2019。
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

# --- PDF 閱讀器路徑清單 ---
$pdfReaderPaths     = @(
    "C:\Program Files (x86)\Foxit Software\Foxit PDF Reader\FoxitPDFReader.exe",
    "C:\Program Files\Foxit Software\Foxit PDF Reader\FoxitPDFReader.exe",
    "C:\FoxitReader\Foxit Reader.exe",
    "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
    "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
)

# --- 通知伺服器設定 ---
$notifyIp           = "220.1.34.75"
$notifyEndpoint     = "/api/notification_json_api.php"
$notifyUrl          = "http://$notifyIp$notifyEndpoint"
$notifyChannels     = @("HA10013859")

# [新增] Admin 通知開關 (控制: 維護摘要、異常/恢復訊息)
$enableAdminNotifications = $false    # 預設不發送自動告警，僅記錄 Log

# [設定] 通知伺服器健康檢查
$enableNotifyHealthCheck = $true      # 開關：是否在啟動時檢查伺服器存活
$notifyTimeoutMs         = 1000       # 逾時：啟動偵測的 Ping 等待時間

# --- 監控時段與頻率 ---
$checkIntervalSec   = 60                  
$errorThreshold     = 5                   
$monitorStartHour   = 8
$monitorEndHour     = 17
$monitorDays        = @("Monday", "Tuesday", "Wednesday", "Thursday", "Friday")

# --- 智慧自癒設定 ---
$enableAutoCleanup  = $true               
$zombieTimeMinutes  = 10                  
$enableAutoHeal     = $true               
$maxStuckPrinters   = 3                   

# --- 排程深度自癒設定 (Cron) ---
$enableScheduledHeal = $true
$scheduledHealCron   = "30 7 * * *"       # 每天早上 07:30 執行

# --- 佇列監控設定 ---
$queueThreshold     = 20                  
$queueStuckLimit    = 5                   

# --- 印表機排除設定 ---
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
    
    if ($objPairs.Count -gt 0) { 
        return "{" + [string]::Join(",", $objPairs) + "}" 
    } else { 
        return """$($InputObject.ToString())""" 
    }
}

function Write-ApiLog {
    param([string]$message)
    try {
        if (-not (Test-Path $logPath)) { [void](New-Item -ItemType Directory -Path $logPath -Force) }
        if (-not (Test-Path $uploadPath)) { [void](New-Item -ItemType Directory -Path $uploadPath -Force) } 
        
        $today = Get-Date -Format "yyyy-MM-dd"
        $fullPath = Join-Path $logPath "PrintApi_$today.log"
        $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $message"
        
        if (Test-Path $fullPath) {
            if ((Get-Item $fullPath).Length -ge $maxLogSizeBytes) {
                if (Test-Path "$fullPath.$maxHistory") { Remove-Item "$fullPath.$maxHistory" -Force }
                for ($i = $maxHistory - 1; $i -ge 1; $i--) {
                    $src = "$fullPath.$i"; $dest = "$fullPath.$($i + 1)"
                    if (Test-Path $src) { Move-Item $src $dest -Force }
                }
                Move-Item $fullPath "$fullPath.1" -Force
            }
        }
        Add-Content -Path $fullPath -Value $logEntry
    } catch {}
}

function Cleanup-OldLogs {
    try {
        if (Test-Path $logPath) {
            $limitDate = (Get-Date).AddDays(-$logRetentionDays)
            $oldFiles = Get-ChildItem -Path $logPath -Filter "PrintApi_*.log*" | Where-Object { $_.LastWriteTime -lt $limitDate }
            if ($null -ne $oldFiles) {
                foreach ($file in $oldFiles) {
                    Write-ApiLog ">>> [日誌清理] 刪除過期日誌: $($file.Name)"
                    Remove-Item $file.FullName -Force
                }
            }
            if (Test-Path $uploadPath) {
                $oldPdfs = Get-ChildItem -Path $uploadPath -Filter "*.pdf" | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-1) }
                if ($null -ne $oldPdfs) { foreach ($pdf in $oldPdfs) { Remove-Item $pdf.FullName -Force } }
            }
        }
    } catch {}
}

function Send-SysAdminNotify {
    param([Parameter(Mandatory=$true)][string]$content, [string]$title = "印表機系統通知")
    
    # --- 檢查頻道是否為空 ---
    if ($null -eq $notifyChannels -or $notifyChannels.Count -eq 0) {
        Write-ApiLog ">>> [通知取消] 頻道列表為空，已略過發送。"
        return
    }

    # --- 檢查全域旗標 ---
    if ($enableNotifyHealthCheck -and (-not $global:IsNotifyServerOnline)) {
        Write-ApiLog ">>> [通知取消] 啟動時偵測到伺服器離線，本週期暫停發送。"
        return
    }

    try {
        $localIp = "127.0.0.1"
        try {
            $ipConfig = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -and $_.IPAddress }
            if ($null -ne $ipConfig) {
                if ($ipConfig -is [array]) { $localIp = $ipConfig[0].IPAddress[0] } else { $localIp = $ipConfig.IPAddress[0] }
            }
        } catch { }
        $fields = @{ "type"="add_notification"; "title"=$title; "content"=$content; "priority"="3"; "sender"="$($env:COMPUTERNAME) ($localIp)"; "from_ip"=$localIp }
        $encodedParts = New-Object System.Collections.Generic.List[string]
        foreach ($key in $fields.Keys) { $encodedParts.Add("$key=$([System.Uri]::EscapeDataString($fields[$key]))") }
        if ($null -ne $notifyChannels) { foreach ($chan in $notifyChannels) { $encodedParts.Add("channels[]=$([System.Uri]::EscapeDataString($chan))") } }
        $postBody = [string]::Join("&", $encodedParts)
        
        Write-ApiLog ">>> [準備發送通知] 標題: $title"
        
        $req = [System.Net.WebRequest]::Create($notifyUrl)
        $req.Method = "POST"
        $req.ContentType = "application/x-www-form-urlencoded"
        $req.Timeout = 500  
        
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($postBody)
        $req.ContentLength = $bytes.Length
        $reqStream = $req.GetRequestStream()
        $reqStream.Write($bytes, 0, $bytes.Length)
        $reqStream.Close()
        
        $resp = $req.GetResponse()
        $resp.Close()
        
        Write-ApiLog ">>> [通知發送成功] 標題: $title"
    } catch { 
        Write-ApiLog "!!! [通知發送失敗] 標題: $title | 錯誤: $($_.Exception.Message) (可能是逾時)" 
    }
}

function Invoke-SpoolerSelfHealing {
    param([string]$reason)
    Write-ApiLog "!!! [自癒啟動] $reason"
    $startMsg = "系統偵測到嚴重異常 ($reason)，正在自動執行深度修復流程。"
    Send-SysAdminNotify -title "?? 系統自動自癒啟動" -content $startMsg
    try {
        Stop-Service "Spooler" -Force; Start-Sleep -Seconds 3
        $spoolPath = "C:\Windows\System32\spool\PRINTERS"
        if (Test-Path $spoolPath) { Get-ChildItem -Path "$spoolPath\*" -Include *.* -Force | Remove-Item -Force }
        Start-Service "Spooler"
        Send-SysAdminNotify -title "? 系統自動自癒完成" -content "服務已重啟並清理暫存檔。"
    } catch { Send-SysAdminNotify -title "? 系統自動自癒失敗" -content "錯誤: $($_.Exception.Message)" }
}

function Test-CronMatch {
    param($cronExpression, $currentTime)
    if ([string]::IsNullOrEmpty($cronExpression)) { return $false }
    $parts = $cronExpression.Split(" ")
    if ($parts.Count -ne 5) { Write-ApiLog "!!! [Cron錯誤] 格式無效: $cronExpression"; return $false }
    
    $min = $parts[0]; $hour = $parts[1]; $dom = $parts[2]; $month = $parts[3]; $dow = $parts[4]
    $curMin = $currentTime.Minute; $curHour = $currentTime.Hour; $curDom = $currentTime.Day; $curMonth = $currentTime.Month; $curDow = [int]$currentTime.DayOfWeek
    
    function Check-Field($pattern, $value) {
        if ($pattern -eq "*") { return $true }
        if ($pattern -match "^(\*|\d+)/(\d+)$") { 
            $step = [int]$matches[2]
            return ($value % $step) -eq 0
        }
        if ($pattern -match ",") { 
            $list = $pattern.Split(",")
            foreach ($item in $list) { if ([int]$item -eq $value) { return $true } }
            return $false
        }
        if ($pattern -match "^(\d+)-(\d+)$") { 
            $start = [int]$matches[1]; $end = [int]$matches[2]
            return ($value -ge $start) -and ($value -le $end)
        }
        return [int]$pattern -eq $value
    }
    return (Check-Field $min $curMin) -and (Check-Field $hour $curHour) -and (Check-Field $dom $curDom) -and (Check-Field $month $curMonth) -and (Check-Field $dow $curDow)
}

function Get-Utf8QueryParam {
    param($request, $key)
    $query = $request.Url.Query
    if ($query -match "[?&]$key=([^&]*)") {
        return [System.Uri]::UnescapeDataString($matches[1])
    }
    return $null
}

function Get-PrinterStatusData {
    $results = New-Object System.Collections.Generic.List[Object]
    $portMap = @{}
    try {
        $tcpPorts = Get-WmiObject -Class Win32_TCPIPPrinterPort -ErrorAction SilentlyContinue
        if ($null -ne $tcpPorts) {
            foreach ($tp in $tcpPorts) { if ($null -ne $tp.Name) { $portMap[$tp.Name] = $tp.HostAddress } }
        }
    } catch {}

    $wmiPrinters = Get-WmiObject -Class Win32_Printer
    $pingSender = New-Object System.Net.NetworkInformation.Ping

    foreach ($p in $wmiPrinters) {
        $pName = $p.Name; $shouldSkip = $false
        foreach ($kw in $excludeKeywords) { if ($pName -like "*$kw*") { $shouldSkip=$true; break } }
        if ($shouldSkip) { continue }
        foreach ($exName in $manualExcludePrinters) { if ($pName -eq $exName) { $shouldSkip=$true; break } }
        if ($shouldSkip) { continue }

        $errorList = New-Object System.Collections.Generic.List[string]
        $isOffline = $false; $isHardwareError = $false
        if ($p.WorkOffline) { $isOffline = $true }
        $errState = $p.DetectedErrorState
        if ($null -ne $errState) {
            if (($errState -band 16) -eq 16) { $errorList.Add("缺紙"); $isHardwareError = $true }
            if (($errState -band 128) -eq 128) { $errorList.Add("機蓋開啟"); $isHardwareError = $true }
            if (($errState -band 256) -eq 256) { $errorList.Add("夾紙"); $isHardwareError = $true }
            if (($errState -band 512) -eq 512) { $isOffline = $true }
            if (($errState -band 1024) -eq 1024) { $errorList.Add("硬體故障"); $isHardwareError = $true }
        }
        
        $finalStatus = "Ready"
        $errDetails = ""
        
        if ($isHardwareError) { 
            $finalStatus = "Error"
            $errDetails = [string]::Join(", ", $errorList)
        } elseif ($isOffline) { 
            $finalStatus = "Offline" 
        } else {
            switch ($p.PrinterStatus) {
                1 { 
                    $finalStatus = "Error"
                    $errDetails = "未知 - 可能原因: 驅動限制/SNMP受阻/特殊硬體狀態"
                }
                2 { 
                    $finalStatus = "Error"
                    $errDetails = "其他 - 請檢查設備面板"
                }
                4 { $finalStatus = "Printing" }
                5 { $finalStatus = "Warmup" }
                default { 
                    $finalStatus = "Ready" 
                    if ($p.PrinterStatus -ne 3) { $finalStatus = "Warning" }
                }
            }
        }
        
        $pPort = $p.PortName; $pIP = ""
        if ($portMap.ContainsKey($pPort)) { $pIP = $portMap[$pPort] } else { $pIP = $pPort }
        
        if ($pIP -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
            try {
                $reply = $pingSender.Send($pIP, 200)
                if ($reply.Status -ne "Success") {
                    if ($finalStatus -eq "Offline") { $errDetails = "無回應 - 可能未開機" }
                    elseif ($finalStatus -like "Ready*") { $finalStatus = "Warning"; $errDetails = "無回應 - 可能斷線或未開機" }
                } else {
                    if ($finalStatus -eq "Offline") { $errDetails = "軟體離線 - 網路通暢" }
                }
            } catch { 
                if ($finalStatus -eq "Offline") { $errDetails = "網路錯誤" }
            }
        }

        $jobCount = 0; if ($null -ne $p.JobCount) { $jobCount = $p.JobCount }
        $pLocation = ""; if ($null -ne $p.Location) { $pLocation = $p.Location }
        $pComment = ""; if ($null -ne $p.Comment) { $pComment = $p.Comment }
        $pDriver = ""; if ($null -ne $p.DriverName) { $pDriver = $p.DriverName }
        $pShareName = ""; if ($p.Shared) { $pShareName = $p.ShareName }

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name $pName
        $obj | Add-Member NoteProperty Status $finalStatus
        $obj | Add-Member NoteProperty Jobs $jobCount
        $obj | Add-Member NoteProperty IP $pIP
        $obj | Add-Member NoteProperty Location $pLocation
        $obj | Add-Member NoteProperty Comment $pComment 
        $obj | Add-Member NoteProperty Driver $pDriver
        $obj | Add-Member NoteProperty PortName $pPort
        $obj | Add-Member NoteProperty ShareName $pShareName
        $obj | Add-Member NoteProperty ErrorDetails $errDetails 
        $results.Add($obj)
    }
    return $results
}

function Test-PrinterHealth {
    Cleanup-OldLogs
    Write-ApiLog ">>> [監控] 巡檢開始..."
    $printers = Get-PrinterStatusData
    $batchAlerts = New-Object System.Collections.Generic.List[string]
    $stuckPrinters = 0
    if ($enableAutoCleanup) {
        $zombies = Get-WmiObject -Class Win32_PrintJob | Where-Object { ($_.JobStatus -like "*Error*" -or $_.JobStatus -like "*Deleting*") }
        if ($null -ne $zombies) {
            foreach ($z in $zombies) { $batchAlerts.Add("?? [自癒] 清理卡住作業: $($z.JobId)"); $z.Delete() }
        }
    }
    foreach ($p in $printers) {
        $name = $p.Name; $pStatus = $p.Status; $pJobs = $p.Jobs; $pDetails = $p.ErrorDetails
        if ($global:IsFirstRun) {
            if ($pStatus -like "Offline*") { $global:ExcludedPrinters[$name] = $true }
            $global:LastQueueCount[$name] = $pJobs; continue
        }
        if ($global:ExcludedPrinters.ContainsKey($name)) {
            if ($pStatus -like "Ready*" -or $pStatus -eq "Printing") { $global:ExcludedPrinters.Remove($name) }
            continue
        }
        if ($pStatus -eq "Error" -or $pStatus -eq "Warning") {
            $global:PrinterErrorCount[$name]++
            if ($global:PrinterErrorCount[$name] -eq $errorThreshold) { 
                $msg = "● [異常] 印表機 [$name] $pStatus"
                if ($pDetails -ne "") { $msg += " ($pDetails)" }
                $batchAlerts.Add($msg) 
            }
        } else {
            if ($global:PrinterErrorCount[$name] -ge $errorThreshold) { $batchAlerts.Add("○ [恢復] 印表機 [$name] 已恢復正常。") }
            $global:PrinterErrorCount[$name] = 0
        }
        if ($pJobs -ge $queueThreshold -and $pJobs -ge $global:LastQueueCount[$name]) {
            $global:QueueStuckCount[$name]++
            if ($global:QueueStuckCount[$name] -eq $queueStuckLimit) {
                $batchAlerts.Add("?? [堵塞] 印表機 [$name] 佇列停滯 ($pJobs 案)。")
                $stuckPrinters++
            }
        } else { $global:QueueStuckCount[$name] = 0 }
        $global:LastQueueCount[$name] = $pJobs
    }
    if ($enableAutoHeal -and $stuckPrinters -ge $maxStuckPrinters) { Invoke-SpoolerSelfHealing -reason "多台印表機同時堵塞"; return }
    if ($global:IsFirstRun) { $global:IsFirstRun = $false; return }
    
    # --- [修正] 檢查 Admin 通知開關 ---
    if ($batchAlerts.Count -gt 0) {
        if ($enableAdminNotifications) {
            Send-SysAdminNotify -content ([string]::Join("`n", $batchAlerts)) -title "印表機維護摘要" 
        } else {
            Write-ApiLog ">>> [監控] 偵測到 $( $batchAlerts.Count ) 筆狀態變更，但 Admin 通知已停用 (EnableAdminNotifications = false)。"
            # 仍將內容寫入日誌以便查核
            foreach ($alert in $batchAlerts) { Write-ApiLog "    |-- $alert" }
        }
    }
}

# -------------------------------------------------------------------------
# 3. 主程序 (HttpListener)
# -------------------------------------------------------------------------
Write-ApiLog "--- 系統初始化: 正在搜尋 PDF 閱讀器 ---"
foreach ($path in $pdfReaderPaths) {
    if (Test-Path $path) {
        $global:ValidPdfReader = $path
        Write-ApiLog "[系統初始化] 已鎖定 PDF 閱讀器: $path"
        break
    }
}
if ($null -eq $global:ValidPdfReader) {
    Write-ApiLog "[系統初始化] 警告: 未偵測到指定清單中的閱讀器，後續列印將降級使用系統預設關聯。"
}

# --- 啟動時偵測通知伺服器 ---
Write-ApiLog "--- 系統初始化: 偵測通知伺服器狀態 ---"
if ($enableNotifyHealthCheck) {
    $pinger = New-Object System.Net.NetworkInformation.Ping
    try {
        $reply = $pinger.Send($notifyIp, $notifyTimeoutMs)
        if ($reply.Status -ne "Success") {
            $global:IsNotifyServerOnline = $false
            Write-ApiLog "[系統初始化] 警告: 通知伺服器 $notifyIp 無回應 (Status: $($reply.Status))。本次運行將停用所有通知。"
        } else {
            Write-ApiLog "[系統初始化] 通知伺服器連線正常。"
        }
    } catch {
        $global:IsNotifyServerOnline = $false
        Write-ApiLog "[系統初始化] 警告: 通知伺服器偵測失敗: $($_.Exception.Message)。本次運行將停用所有通知。"
    }
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://*:$port/")
try { $listener.Start(); Write-ApiLog "--- 伺服器 v16.9 上線 (Admin 通知旗標已啟用: $enableAdminNotifications) ---" } catch { exit }

$nextCheck = Get-Date; $nextHeart = Get-Date; $contextTask = $null

while ($listener.IsListening) {
    try {
        $now = Get-Date
        if ($now -ge $nextHeart) { Write-ApiLog "[存活] 監聽中..."; $nextHeart = $now.AddSeconds(60) }
        
        # 定時健康檢查
        if ($now -ge $nextCheck) {
            $day = $now.DayOfWeek.ToString()
            if (($now.Hour -ge $monitorStartHour) -and ($now.Hour -lt $monitorEndHour) -and ($monitorDays -contains $day)) {
                Test-PrinterHealth
            } else { Write-ApiLog ">>> [非工作時段] 跳過巡檢。" }
            $nextCheck = $now.AddSeconds($checkIntervalSec)
        }

        # Cron 排程自癒
        if ($enableScheduledHeal) {
            if ($global:LastCronRunTime -eq $null -or ($now.Minute -ne $global:LastCronRunTime.Minute -or $now.Hour -ne $global:LastCronRunTime.Hour)) {
                if (Test-CronMatch $scheduledHealCron $now) {
                    Write-ApiLog ">>> [排程] Cron 觸發 ($scheduledHealCron)，執行深度自癒。"
                    Invoke-SpoolerSelfHealing -reason "Cron 排程自動維護"
                    $global:LastCronRunTime = $now
                }
            }
        }

        if ($null -eq $contextTask) { $contextTask = $listener.BeginGetContext($null, $null) }
        if (-not $contextTask.AsyncWaitHandle.WaitOne(1000)) { continue }

        $context = $listener.EndGetContext($contextTask); $contextTask = $null
        $request = $context.Request; $response = $context.Response; $path = $request.Url.AbsolutePath.ToLower()
        Write-ApiLog ">>> [請求] 來自: $($request.RemoteEndPoint) 路徑: $path"

        # --- [CORS] ---
        $response.AddHeader("Access-Control-Allow-Origin", "*")
        $response.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        $response.AddHeader("Access-Control-Allow-Headers", "*") 

        if ($request.HttpMethod -eq "OPTIONS") {
            $response.StatusCode = 200; $response.Close()
            Write-ApiLog ">>> [CORS] 預檢請求通過"; continue
        }

        $res = @{ "success"=$false; "message"=""; "data"=$null }
        if ($request.Headers["X-API-KEY"] -ne $apiKey) { $response.StatusCode = 401 }
        else {
            if ($path -eq "/printers") { 
                $res.data = Get-PrinterStatusData; $res.success = $true
                $res.message = "已成功取得所有印表機列表"
            }
            elseif ($path -eq "/server/logs") {
                $todayLog = Join-Path $logPath "PrintApi_$(Get-Date -Format 'yyyy-MM-dd').log"
                if (Test-Path $todayLog) {
                    $linesReq = Get-Utf8QueryParam $request "lines" 
                    $count = 100
                    if ($null -ne $linesReq -and $linesReq -match "^\d+$") { $count = [int]$linesReq }
                    $logContent = Get-Content $todayLog | Select-Object -Last $count
                    $res.data = $logContent; $res.success = $true; $res.message = "已讀取最後 $count 行日誌"
                } else { $res.message = "今日尚無日誌檔案" }
            }
            elseif ($path -eq "/server/restart-script") {
                $res.success = $true
                $res.message = "API 伺服器正在重新啟動中..."
                Write-ApiLog ">>> [系統操作] 收到重啟指令 (Restart Script)"
                $restartScript = $true
            }
            elseif ($path -eq "/printer/update") {
                $pName = Get-Utf8QueryParam $request "name"
                $pLoc  = Get-Utf8QueryParam $request "location"
                $pCom  = Get-Utf8QueryParam $request "comment"
                $pObj = Get-WmiObject -Class Win32_Printer | Where-Object { $_.Name -eq $pName }
                if ($null -ne $pObj) {
                    $updates = @()
                    if ($null -ne $pLoc) { $pObj.Location = $pLoc; $updates += "位置" }
                    if ($null -ne $pCom) { $pObj.Comment = $pCom; $updates += "備註" }
                    if ($updates.Count -gt 0) {
                        try {
                            $pObj.Put()
                            $res.success = $true; $res.message = "印表機 [$pName] 資料更新成功"
                            Send-SysAdminNotify -content "API：印表機 [$pName] 基本資料已更新。" -title "資產管理"
                        } catch { $res.message = "更新失敗: $($_.Exception.Message)" }
                    } else { $res.message = "未提供需更新的欄位" }
                } else { $res.message = "找不到指定的印表機" }
            }
            elseif ($path -eq "/printer/print-pdf") {
                if ($request.HttpMethod -eq "POST") {
                    $pName = Get-Utf8QueryParam $request "name" 
                    $pObj = Get-WmiObject Win32_Printer | Where-Object { $_.Name -eq $pName }
                    
                    if ($null -ne $pObj) {
                        $duplexReq = Get-Utf8QueryParam $request "duplex" 
                        $restoreDuplex = $false; $oldDuplexMode = $null
                        
                        if ($null -ne $duplexReq) {
                            if (Get-Command Set-PrintConfiguration -ErrorAction SilentlyContinue) {
                                try {
                                    $currentCfg = Get-PrintConfiguration -PrinterName $pName -ErrorAction Stop
                                    $oldDuplexMode = $currentCfg.DuplexingMode
                                    $targetMode = "OneSided"
                                    if ($duplexReq -eq "1" -or $duplexReq -eq "long") { $targetMode = "TwoSidedLongEdge" }
                                    elseif ($duplexReq -eq "2" -or $duplexReq -eq "short") { $targetMode = "TwoSidedShortEdge" }
                                    
                                    if ($oldDuplexMode -ne $targetMode) {
                                        Write-ApiLog ">>> [設定] 切換雙面模式: $targetMode"
                                        Set-PrintConfiguration -PrinterName $pName -DuplexingMode $targetMode -ErrorAction Stop
                                        $restoreDuplex = $true
                                    }
                                } catch { Write-ApiLog ">>> [設定警告] 無法變更雙面設定: $($_.Exception.Message)" }
                            } else { Write-ApiLog ">>> [忽略] 不支援 Set-PrintConfiguration" }
                        }

                        $fileName = "Upload_$(Get-Date -Format 'yyyyMMdd_HHmmss').pdf"
                        $savePath = Join-Path $uploadPath $fileName
                        Write-ApiLog ">>> [上傳] 接收 PDF: $fileName"
                        
                        $fs = New-Object System.IO.FileStream($savePath, [System.IO.FileMode]::Create)
                        $buffer = New-Object byte[] 8192
                        do {
                            $read = $request.InputStream.Read($buffer, 0, $buffer.Length)
                            if ($read -gt 0) { $fs.Write($buffer, 0, $read) }
                        } while ($read -gt 0); $fs.Close()
                        
                        Write-ApiLog ">>> [列印] 調用 PDF 閱讀器..."
                        try {
                            if ($null -ne $global:ValidPdfReader) {
                                Write-ApiLog ">>> [列印] 使用快取路徑: $($global:ValidPdfReader)"
                                $argList = "/t ""$savePath"" ""$pName"""
                                $proc = Start-Process -FilePath $global:ValidPdfReader -ArgumentList $argList -PassThru -WindowStyle Hidden
                                $proc.WaitForExit(10000)
                            } else {
                                Write-ApiLog ">>> [列印] 嘗試 Shell PrintTo (未偵測到指定閱讀器)..."
                                $proc = Start-Process -FilePath $savePath -Verb PrintTo -ArgumentList """$pName""" -PassThru -WindowStyle Hidden
                                $proc.WaitForExit(10000)
                            }
                            $res.success = $true; $res.message = "PDF 已傳送至列印佇列"
                            Send-SysAdminNotify -content "API：PDF 上傳並發送至 [$pName] (雙面:$($null -ne $duplexReq))。" -title "遠端列印"
                        } catch {
                            $res.message = "列印失敗: $($_.Exception.Message)"
                            Write-ApiLog "!!! [列印錯誤] $($_.Exception.Message)"
                        }

                        if ($restoreDuplex) {
                            try {
                                Write-ApiLog ">>> [還原] 恢復雙面設定"
                                Set-PrintConfiguration -PrinterName $pName -DuplexingMode $oldDuplexMode -ErrorAction SilentlyContinue
                            } catch {}
                        }
                    } else { $res.message = "找不到指定的印表機: $pName" }
                } else { $res.message = "僅支援 POST 方法" }
            }
            elseif ($path -eq "/printer/status") {
                $pName = Get-Utf8QueryParam $request "name" 
                $all = Get-PrinterStatusData
                $target = $null
                foreach($item in $all) { if($item.Name -eq $pName) { $target = $item; break } }
                if ($null -ne $target) { 
                    $res.data = $target; $res.success = $true
                    $res.message = "已成功取得印表機 [$pName] 狀態"
                }
                else { $res.message = "找不到指定的印表機" }
            }
            elseif ($path -eq "/printer/refresh") {
                $pName = Get-Utf8QueryParam $request "name" 
                $pObj = Get-WmiObject -Class Win32_Printer | Where-Object { $_.Name -eq $pName }
                if ($null -ne $pObj) {
                    $pObj.Pause(); Start-Sleep -Milliseconds 500; $pObj.Resume()
                    $res.success = $true
                    $res.message = "印表機 [$pName] 重新整理指令已執行"
                    Send-SysAdminNotify -content "API：印表機 [$pName] 手動重新整理成功。" -title "維護操作"
                } else { $res.message = "找不到指定的印表機" }
            }
            elseif ($path -eq "/printer/clear") {
                $pName = Get-Utf8QueryParam $request "name" 
                $jobs = Get-WmiObject Win32_PrintJob | Where-Object { $_.Name -like "*$pName*" }
                if ($jobs) { foreach($j in $jobs){$j.Delete()} }
                $res.success = $true
                $res.message = "印表機 [$pName] 佇列清除指令已執行"
                Send-SysAdminNotify -content "[$pName] 手動清理完成。" -title "手動操作"
            }
            elseif ($path -eq "/service/restart-spooler") {
                try {
                    Restart-Service "Spooler" -Force
                    $res.success = $true
                    $res.message = "Spooler 服務已成功重啟"
                    Send-SysAdminNotify -content "API：Spooler 服務已重啟。" -title "服務操作"
                } catch { Write-ApiLog "!!! [重啟失敗] $($_.Exception.Message)" }
            }
            elseif ($path -eq "/service/self-heal") {
                Invoke-SpoolerSelfHealing -reason "管理員遠端發動深度修復"; $res.success = $true
                $res.message = "深度自癒流程已啟動"
            }
            else { 
                $response.StatusCode = 404 
                Write-ApiLog "!!! [路徑錯誤] 無法辨識的路徑: $path"
            }
        }

        $buffer = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-SimpleJson $res))
        $response.ContentType = "application/json"
        
        try {
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.Close()
            Write-ApiLog "<<< [完成] $clientIP 的請求處理週期結束。"
        } catch {
            Write-ApiLog ">>> [連線中斷] 客戶端 $clientIP 在回應傳輸前斷開 ($($_.Exception.Message))"
        }

        if ($restartScript) {
            Write-ApiLog ">>> [系統重啟] 正在釋放資源並啟動新程序..."
            try { $listener.Stop(); $listener.Close() } catch {}
            $myself = $MyInvocation.MyCommand.Definition
            Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$myself`"" -WindowStyle Hidden
            exit
        }

    } catch { 
        Write-ApiLog "!!! [系統錯誤] $($_.Exception.Message)"
        $contextTask = $null 
    }
}