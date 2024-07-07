<#
.SYNOPSIS
    The Prober
    The Prober aims to be an all-in-one enumeration tool, like WinPeas but potentially cooler.

.DESCRIPTION
    The Prober aims to be an all-in-one enumeration tool, like WinPeas but potentially cooler.

.PARAMETER SaveLocation
    File save location. Defaults to the current directory if not specified.

.PARAMETER NoConfig
    Switch to disable creation of the configuration file.

.PARAMETER Version
    Displays the script version information.

.EXAMPLE
    .\pr0ber.ps1 -SaveLocation "C:\Scans" -NoConfig

    Captures a bunch of things, saving results to "C:\Scans" without creating a configuration file.

.NOTES
    Script Version: 0.1
    Created by Dean with a touch of care.
    For more details, visit: https://github.com/deannreid/The-Prober

    Don't be a dick. Only use this if you are legally allowed to do so.
#>

# Setup Params
param (
    [string]$SaveLocation = (Get-Location).Path,
    [switch]$NoConfig,
    [switch]$Version
)

# Define the configuration file path
$CONFIG_FILE_DIR = Join-Path -Path $env:USERPROFILE -ChildPath ".TheProber"
$CONFIG_FILE = Join-Path -Path $CONFIG_FILE_DIR -ChildPath "config.cfg"

function dsplAsciiBanner {
    Write-Host -ForegroundColor Cyan @"
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░      ░▒▓███████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░  
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓██████▓▒░        ░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░  
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                                                              
                                Your future all-in-one penetration testing enumeration tool.
                                                Like WinPeas but maybe cooler?

                                      ------------------------------------------------
                                      ::        %INSERT RELEVANT DISCORD HERE       ::
                                      ::   https://github.com/deannreid/The-Prober  ::
                                      ------------------------------------------------
"@
}

function dsplMessage {
    param (
        [string]$Message,
        [string]$Type
    )
    switch ($Type) {
        "info" { Write-Host -ForegroundColor Cyan "{~} $Message" }
        "warning" { Write-Host -ForegroundColor Red "{!} $Message" }
        "success" { Write-Host -ForegroundColor Green "{✓} $Message" }
        "error" { Write-Host -ForegroundColor Red "{!} $Message" }
        "disabled" { Write-Host -ForegroundColor Gray "{X} $Message" }
        default { Write-Host "$Message" }
    }
}

function dsplBlurb {
    $blurbs = @(
        "                          Enumerating services: Like snooping on your neighbor's Wi-Fi, but legal.`n",
        "                          Exploring services: The geek's way of saying 'I'm just curious!`n",
        "                          Discovering endpoints: Like a treasure hunt, but with more IP addresses.`n",
        "                          Probing the depths: Finding the hidden gems in your network.`n"
    )
    $randomIndex = Get-Random -Minimum 0 -Maximum $blurbs.Length
    Write-Host $blurbs[$randomIndex]
}

function fncConfigCheck {
    if (-not $NoConfig) {
        if (-not (Test-Path $CONFIG_FILE)) {
            dsplMessage "Configuration file not found: $CONFIG_FILE" "warning"
            New-Item -ItemType Directory -Path $CONFIG_FILE_DIR -Force
            New-Item -ItemType File -Path $CONFIG_FILE -Force
            dsplMessage "Configuration file created: $CONFIG_FILE" "success"
        } else {
            dsplMessage "Configuration file found: $CONFIG_FILE" "info"
        }
    } else {
        dsplMessage "Configuration creation disabled by user." "info"
    }
}

function dsplVersion {
    Write-Host -ForegroundColor Cyan @"
==============================================
| The Prober - Windows Enumaration Tool      |
| Version: 1.9.5                             |
|                                            |
| Created by Dean with a touch of care       |
==============================================
| Script Details:                            |
| Like WinPeas but maybe cooler?             |
|                                            |
==============================================
| Change Log:                                |
| 06/07/2024: Initial Code Build             |
==============================================
"@
}

function fncVerifyPSVersion {
    $psVersion = $PSVersionTable.PSVersion
    dsplMessage "Detected PowerShell Version: $psVersion" "info"
    if ($psVersion.Major -lt 5) {
        dsplMessage "This script requires PowerShell 5.0 or higher. Please upgrade your PowerShell version." "error"
        exit 1
    }
}

function fncCheckIfAdmin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function fncB64Enc {
    param (
        [string]$filePath,
        [string]$encodedFilePath
    )

    try {
        # Read all content of the file as bytes
        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)

        # Convert bytes to Base64 string
        $base64String = [System.Convert]::ToBase64String($fileBytes)

        # Write the Base64 string to a file
        $base64String | Out-File -FilePath $encodedFilePath -Encoding utf8
        Write-Host "Successfully encoded $filePath to base64: $encodedFilePath"
    } catch {
        Write-Host "Failed to encode file to base64: $_"
    }
}

# Function to write output to a file
function fncWriteToFile {
    param (
        [string]$functionName,
        [string]$output
    )
    try {
        if ($null -eq $output -or $output -eq '') {
            Write-Host "No output received from function $functionName. Skipping file write."
            return
        }

        # It's a bit Broken right now...
        #$hostName = $env:COMPUTERNAME
        #$scriptDir = $PSScriptRoot
        #$fileName = Join-Path -Path $scriptDir -ChildPath "$hostName-$functionName.txt"

        #Write-Host "Writing output of $functionName to $fileName"
        $output | Out-File -FilePath $fileName -Encoding utf8
        Write-Host "Successfully wrote output of $functionName to $fileName"
    } catch {
        Write-Host "Failed to write output of $functionName to file. Error: $_"
    }
}

############################################
##### Functions that actually do stuff.#####
############################################
function Get-SystemInformation {
    dsplMessage "System Information" "info"
    Write-Host "================="

    # Get computer name
    $computerName = $env:COMPUTERNAME
    Write-Host "Computer Name: $computerName"

    # Get operating system details
    $operatingSystem = (Get-WmiObject Win32_OperatingSystem).Caption
    Write-Host "Operating System: $operatingSystem"

    # Get system architecture
    $architecture = (Get-WmiObject Win32_ComputerSystem).SystemType
    Write-Host "System Architecture: $architecture"

    # Get current logged-on user
    $currentUser = $env:USERNAME
    Write-Host "Current User: $currentUser"

    # Get last boot time
    $lastBootTime = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
    $lastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime($lastBootTime)
    Write-Host "Last Boot Time: $lastBootTime"

    # Get uptime
    $uptime = (Get-Date) - (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
    Write-Host "Uptime: $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"

    # Get BIOS information
    $bios = Get-WmiObject Win32_BIOS
    Write-Host "BIOS Version: $($bios.SMBIOSBIOSVersion)"
    Write-Host "Manufacturer: $($bios.Manufacturer)"
    Write-Host "Release Date: $($bios.ConvertToDateTime($bios.ReleaseDate))"

    # Get physical memory (RAM)
    $memory = Get-WmiObject Win32_ComputerSystem
    $totalMemoryGB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
    Write-Host "Total Physical Memory: $totalMemoryGB GB"

    # Get processor information
    $processor = Get-WmiObject Win32_Processor
    Write-Host "Processor: $($processor.Name)"
    Write-Host "Number of Cores: $($processor.NumberOfCores)"
    Write-Host "Max Clock Speed: $($processor.MaxClockSpeed) MHz"

    # Get system drive information
    $systemDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
    $systemDriveSizeGB = [math]::Round($systemDrive.Size / 1GB, 2)
    $systemDriveFreeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    Write-Host "System Drive (C:) Size: $systemDriveSizeGB GB"
    Write-Host "System Drive (C:) Free Space: $systemDriveFreeSpaceGB GB"
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-AvailableDrives {
    dsplMessage "Available Drives" "info"
    Write-Host "================"

    # Get all drives using Get-PSDrive
    $drives = Get-PSDrive -PSProvider FileSystem

    foreach ($drive in $drives) {
        $driveLetter = $drive.Name
        $driveLabel = $drive.VolumeLabel
        $driveTotalSizeGB = [math]::Round($drive.Used + $drive.Free / 1GB, 2)
        $driveFreeSpaceGB = [math]::Round($drive.Free / 1GB, 2)

        # Check if drive is SMB drive
        $isSmbDrive = $drive.Root -like "\\*"

        Write-Host "Drive: $driveLetter"
        Write-Host "Label: $driveLabel"
        Write-Host "Total Size: $driveTotalSizeGB GB"
        Write-Host "Free Space: $driveFreeSpaceGB GB"

        if ($isSmbDrive) {
            Write-Host "Drive Type: SMB Drive"
        } else {
            Write-Host "Drive Type: Local Drive"
        }

        Write-Host ""
    }
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-AntivirusDetections {
    dsplMessage "Installed Antivirus Software" "info"
    Write-Host "================"

    # Retrieve antivirus information using WMI
    $antivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct

    if ($antivirus) {
        foreach ($product in $antivirus) {
            Write-Host "Name: $($product.displayName)"
            Write-Host "Path: $($product.pathToSignedProductExe)"
            Write-Host "State: $($product.productState)"
            
            # Vendor Information
            if ($product.vendor) {
                Write-Host "Vendor: $($product.vendor)"
            }

            # Version Information
            if ($product.version) {
                Write-Host "Version: $($product.version)"
            }

            # Additional Properties
            Write-Host "Is Enabled: $($product.productState -eq 397568)"
            Write-Host "Is Updated: $($product.productState -eq 397584)"
            Write-Host "Is Virus Scanner: $($product.productState -eq 393472)"

            Write-Host ""
        }
    } else {
        dsplMessage "No antivirus products found." "info"
    }
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-InstalledKB {
    dsplMessage "Installed KB Updates" "info"
    Write-Host "================="

    # Retrieve installed KB updates using WMI and sort by InstalledOn descending
    $installedKB = Get-WmiObject -Class Win32_QuickFixEngineering | Sort-Object -Property InstalledOn -Descending

    if ($installedKB) {
        foreach ($kb in $installedKB) {
            Write-Host "Hotfix ID: $($kb.HotFixID)"
            Write-Host "Description: $($kb.Description)"
            
            # Format InstalledOn date to UK format (DD/MM/YYYY)
            $installedOnUK = Get-Date -Date $kb.InstalledOn -Format "dd/MM/yyyy"
            Write-Host "Installed On: $installedOnUK"

            # Additional information if available
            if ($kb.ServicePackInEffect) {
                Write-Host "Service Pack in Effect: $($kb.ServicePackInEffect)"
            }
            if ($kb.InstalledBy) {
                Write-Host "Installed By: $($kb.InstalledBy)"
            }
            if ($kb.Caption) {
                Write-Host "Caption: $($kb.Caption)"
            }
            if ($kb.Severity) {
                Write-Host "Severity: $($kb.Severity)"
            }
            
            Write-Host ""
        }
    } else {
        dsplMessage "No installed KB updates found." "info"
    }
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-RunningServices {
    dsplMessage "Running Services" "info"
    Write-Host "================"

    # Retrieve running services using Get-Service cmdlet
    $runningServices = Get-Service | Where-Object { $_.Status -eq 'Running' }

    if ($runningServices) {
        foreach ($service in $runningServices) {
            Write-Host "Service Name: $($service.Name)"
            Write-Host "Display Name: $($service.DisplayName)"
            Write-Host "Status: $($service.Status)"
            Write-Host "Start Type: $($service.StartType)"

            # Additional information if available
            if ($service.Description) {
                Write-Host "Description: $($service.Description)"
            }
            if ($service.MachineName) {
                Write-Host "Machine Name: $($service.MachineName)"
            }
            if ($service.ServiceType) {
                Write-Host "Service Type: $($service.ServiceType)"
            }
            if ($service.CanPauseAndContinue) {
                Write-Host "Can Pause and Continue: $($service.CanPauseAndContinue)"
            }
            if ($service.CanShutdown) {
                Write-Host "Can Shutdown: $($service.CanShutdown)"
            }
            if ($service.CanStop) {
                Write-Host "Can Stop: $($service.CanStop)"
            }
            if ($service.Started) {
                Write-Host "Started: $($service.Started)"
            }
            if ($service.StartName) {
                Write-Host "Start Name: $($service.StartName)"
            }
            if ($service.PathName) {
                Write-Host "Path Name: $($service.PathName)"
            }
            if ($service.ServiceHandle) {
                Write-Host "Service Handle: $($service.ServiceHandle)"
            }
            if ($service.Site) {
                Write-Host "Site: $($service.Site)"
            }
            if ($service.InstallDate) {
                $installDate = Get-Date -Date $service.InstallDate -Format "dd/MM/yyyy HH:mm:ss"
                Write-Host "Install Date: $($installDate)"
            }
            if ($service.PSComputerName) {
                Write-Host "PSComputerName: $($service.PSComputerName)"
            }

            Write-Host ""
        }
    } else {
        dsplMessage "No running services found." "info"
    }
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-PasswordPolicy {
    dsplMessage "Password Policy Settings" "info"
    Write-Host "================"

    try {
        # Execute net accounts command to retrieve password policy settings
        $netAccounts = & net accounts

        if ($netAccounts) {
            # Extract relevant information
            $passwordComplexity = $netAccounts | Select-String -Pattern "Password complexity"
            $passwordLength = $netAccounts | Select-String -Pattern "Minimum password length"
            $maxPasswordAge = $netAccounts | Select-String -Pattern "Maximum password age"
            $minPasswordAge = $netAccounts | Select-String -Pattern "Minimum password age"
            $passwordHistory = $netAccounts | Select-String -Pattern "Password history"

            # Display settings
            Write-Host $passwordComplexity
            Write-Host $passwordLength
            Write-Host $maxPasswordAge
            Write-Host $minPasswordAge
            Write-Host $passwordHistory
        } else {
            dsplMessage "Unable to retrieve password policy settings." "info"
        }
    } catch {
        dsplMessage "Error occurred while retrieving password policy settings: $_" "error"
    }
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-LocalUsers {
    dsplMessage "Local User Accounts" "info"
    Write-Host "==================="

    try {
        # Retrieve local user accounts using Get-WmiObject
        $localUsers = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }
        if ($localUsers) {
            foreach ($user in $localUsers) {
                Write-Host "User Name: $($user.Name)"
                Write-Host "SID: $($user.SID)"
                Write-Host "Full Name: $($user.FullName)"
                Write-Host "Description: $($user.Description)"
                Write-Host "Account Type: $($user.AccountType)"
                Write-Host ""
            }
        } else {
            dsplMessage "No local user accounts found." "info"
        }
    } catch {
        dsplMessage "Error occurred while retrieving local user accounts: $_" "error"
    }
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-LocalGroups {
    dsplMessage "Local Groups" "info"
    Write-Host "============"

    try {
        # Retrieve local groups using Get-WmiObject
        $localGroups = Get-WmiObject -Class Win32_Group | Where-Object { $_.LocalAccount -eq $true }
        if ($localGroups) {
            foreach ($group in $localGroups) {
                Write-Host "Group Name: $($group.Name)"
                Write-Host "SID: $($group.SID)"
                Write-Host "Description: $($group.Description)"
                Write-Host ""
            }
        } else {
            dsplMessage "No local groups found." "info"
        }
    } catch {
        dsplMessage "Error occurred while retrieving local groups: $_" "error"
    }
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-InstalledSoftware {
    dsplMessage "Installed Software" "info"
    Write-Host "=================="

    try {
        # Define registry path where installed software information is stored
        $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"

        # Retrieve software information from registry
        $softwareList = Get-ItemProperty -Path $registryPath |
                        Where-Object { $_.DisplayName -and $_.DisplayName -notlike "Security Update*" } |
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

        if ($softwareList) {
            # Display software information
            foreach ($software in $softwareList) {
                Write-Host "Name: $($software.DisplayName)"
                Write-Host "Version: $($software.DisplayVersion)"
                Write-Host "Publisher: $($software.Publisher)"
                if ($software.InstallDate) {
                    $installDate = [DateTime]::ParseExact($software.InstallDate, "yyyyMMdd", $null)
                    Write-Host "Install Date: $($installDate.ToString('dd/MM/yyyy'))"
                }
                Write-Host ""
            }
        } else {
            dsplMessage "No software found." "info"
        }
    } catch {
        dsplMessage "Error occurred while retrieving installed software: $_" "error"
    }
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-OpenPorts {
    dsplMessage "Open Ports" "info"
    dsplMessage "===========" "info"
    try {
        # Define an array of common ports to check for Windows Server
        $ports = @(80, 443, 3389, 445, 135, 137, 139, 1433, 1521, 3306, 5985, 5986, 464, 3268, 3269, 53, 88, 389, 636)
        $tasks = @()

        # Function to display progress message
        function dsplProgress {
            param($message)
            Write-Host ""
            dsplMessage "$message" "info"
        }

        dsplProgress "Initiating port checks..."

        foreach ($port in $ports) {
            # Start an asynchronous task for each port check
            $task = {
                param($port)
                $result = Test-NetConnection -ComputerName localhost -Port $port -InformationLevel Quiet -ErrorAction SilentlyContinue
                if ($result.TcpTestSucceeded) {
                    [PSCustomObject]@{
                        Port = $port
                        RemoteAddress = $result.RemoteAddress
                        RemotePort = $result.RemotePort
                    }
                }
            }

            $tasks += Start-Job -ScriptBlock $task -ArgumentList $port
            Write-Host "Checking port $port..."
        }

        dsplProgress "Waiting for port checks to complete..."

        # Wait for all jobs to finish with a 5-second timeout
        foreach ($job in $tasks) {
            $job | Wait-Job -Timeout 5
        }

        dsplProgress "Port checks completed. Results:"

        # Get the results of completed jobs
        foreach ($job in $tasks) {
            if ($job.State -eq 'Completed') {
                $result = Receive-Job -Job $job
                if ($result) {
                    Write-Host "Port $($result.Port) is open"
                    Write-Host "    Remote Address: $($result.RemoteAddress)"
                    Write-Host "    Remote Port: $($result.RemotePort)"
                    Write-Host ""
                }
            } else {
                Write-Host "Port check for job $($job.Id) timed out."
            }
            Remove-Job -Job $job
        }

        dsplProgress "Port scanning finished."
    } catch {
        dsplMessage "Error occurred while checking open ports: $_" "error"
    }
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-Netstat {
    dsplMessage "Network Statistics (netstat equivalent)" "info"
    dsplMessage "===================================" "info"

    try {
        # Get active TCP connections
        $tcpConnections = Get-NetTCPConnection -ErrorAction Stop

        # Display active TCP connections
        dsplMessage "Active TCP Connections:" "info"
        foreach ($conn in $tcpConnections) {
            Write-Host "Local Address: $($conn.LocalAddress):$($conn.LocalPort)"
            Write-Host "Remote Address: $($conn.RemoteAddress):$($conn.RemotePort)"
            Write-Host "State: $($conn.State)"
            Write-Host ""
        }

        # Get UDP endpoints
        $udpConnections = Get-NetUDPEndpoint -ErrorAction Stop

        # Display UDP endpoints
        dsplMessage "UDP Endpoints:" "info"
        foreach ($udp in $udpConnections) {
            Write-Host "Local Address: $($udp.LocalAddress):$($udp.LocalPort)"
            Write-Host "Remote Address: $($udp.RemoteAddress):$($udp.RemotePort)"
            Write-Host ""
        }

        dsplMessage "Netstat command completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while running netstat: $_" "error"
    }
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-FirewallRules {
    dsplMessage "Firewall Rules" "info"
    Write-Host "==============="

    try {
        # Attempt to get firewall rules
        $rules = Get-NetFirewallRule -ErrorAction Stop

        # Display firewall rules
        foreach ($rule in $rules) {
            Write-Host "Name: $($rule.DisplayName)"
            Write-Host "Enabled: $($rule.Enabled)"
            Write-Host "Direction: $($rule.Direction)"
            Write-Host "Action: $($rule.Action)"
            Write-Host "Profile: $($rule.Profile)"
            Write-Host "LocalPort: $($rule.LocalPort)"
            Write-Host "RemotePort: $($rule.RemotePort)"
            Write-Host "LocalAddress: $($rule.LocalAddress)"
            Write-Host "RemoteAddress: $($rule.RemoteAddress)"
            Write-Host "Protocol: $($rule.Protocol)"
            Write-Host ""
        }

        dsplMessage "Firewall rules retrieval completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while retrieving firewall rules: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-NetworkShares {
    dsplMessage "Network Shares" "info"
    Write-Host "==============="

    try {
        # Get network shares using WMI
        $shares = Get-WmiObject -Class Win32_Share -ErrorAction Stop

        # Display network shares
        foreach ($share in $shares) {
            Write-Host "Name: $($share.Name)"
            Write-Host "Path: $($share.Path)"
            Write-Host "Description: $($share.Description)"
            Write-Host ""
        }

        dsplMessage "Network shares retrieval completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while retrieving network shares: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-RecentFiles {
    dsplMessage "Recent Files" "info"
    Write-Host "==============="

    try {
        # Define the path to the user's Recent folder
        $recentFolder = [System.IO.Path]::Combine($env:USERPROFILE, "AppData\Roaming\Microsoft\Windows\Recent")

        # Get recent files from the Recent folder
        $recentFiles = Get-ChildItem -Path $recentFolder -File | Sort-Object LastWriteTime -Descending | Select-Object -First 10

        # Display recent files
        foreach ($file in $recentFiles) {
            Write-Host "Name: $($file.Name)"
            Write-Host "Path: $($file.FullName)"
            Write-Host "Last Modified: $($file.LastWriteTime)"
            Write-Host ""
        }

        dsplMessage "Recent files retrieval completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while retrieving recent files: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-StartupPrograms {
    dsplMessage "Startup Programs" "info"
    Write-Host "==============="

    try {
        # Define the Registry path for startup programs
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

        # Get startup programs from Registry
        $startupPrograms = Get-ItemProperty -Path $regPath | Select-Object -Property PSChildName, DisplayName, CommandLine

        # Display startup programs
        foreach ($program in $startupPrograms) {
            Write-Host "Name: $($program.PSChildName)"
            Write-Host "Display Name: $($program.DisplayName)"
            Write-Host "Command Line: $($program.CommandLine)"
            Write-Host ""
        }

        dsplMessage "Startup programs retrieval completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while retrieving startup programs: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-SystemLogs {
    dsplMessage "System Logs" "info"
    Write-Host "==============="

    try {
        # Get setup logs
        Write-Host "Setup Logs:"
        $setupLogs = Get-EventLog -LogName "Setup" -Newest 10 -ErrorAction Stop
        foreach ($log in $setupLogs) {
            Write-Host "Entry Type: $($log.EntryType)"
            Write-Host "Message: $($log.Message)"
            Write-Host ""
        }

        # Get system event logs if Setup logs exist
        Write-Host "System Event Logs:"
        Get-EventLog -LogName "System" -Newest 10 | ForEach-Object {
            Write-Host "Entry Type: $($_.EntryType)"
            Write-Host "Message: $($_.Message)"
            Write-Host ""
        }

        dsplMessage "System logs retrieval completed successfully." "success"
    } catch {
        if ($_.Exception.Message -like "*The system cannot find the file specified.*") {
            dsplMessage "Setup logs not found or inaccessible." "info"
        } else {
            dsplMessage "Error occurred while retrieving system logs: $_" "error"
        }
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-EventLogs {
    dsplMessage "Event Logs" "info"
    Write-Host "==============="

    try {
        # Get application event logs
        Write-Host "Application Event Logs:"
        Get-EventLog -LogName "Application" -Newest 10 | ForEach-Object {
            Write-Host "Entry Type: $($_.EntryType)"
            Write-Host "Message: $($_.Message)"
            Write-Host ""
        }

        # Get security event logs
        Write-Host "Security Event Logs:"
        Get-EventLog -LogName "Security" -Newest 10 | ForEach-Object {
            Write-Host "Entry Type: $($_.EntryType)"
            Write-Host "Message: $($_.Message)"
            Write-Host ""
        }

        # Get PowerShell event logs
        Write-Host "PowerShell Event Logs:"
        Get-EventLog -LogName "Windows PowerShell" -Newest 10 | ForEach-Object {
            Write-Host "Entry Type: $($_.EntryType)"
            Write-Host "Message: $($_.Message)"
            Write-Host ""
        }

        dsplMessage "Event logs retrieval completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while retrieving event logs: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

# TODO: Get more registry keys 
function Get-RegistrySettings {
    dsplMessage "Registry Settings" "info"
    Write-Host "==============="

    try {
        # Define the Registry path to query
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

        # Get registry settings
        $registrySettings = Get-ItemProperty -Path $regPath

        # Display specific registry settings
        Write-Host "Product Name: $($registrySettings.ProductName)"
        Write-Host "Current Version: $($registrySettings.CurrentVersion)"
        Write-Host "Install Date: $($registrySettings.InstallDate)"
        Write-Host "Registered Owner: $($registrySettings.RegisteredOwner)"
        Write-Host "System Root: $($registrySettings.SystemRoot)"
        Write-Host "BuildLab: $($registrySettings.BuildLab)"

        dsplMessage "Registry settings retrieval completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while retrieving registry settings: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-EnvironmentVariables {
    dsplMessage "Environment Variables" "info"
    Write-Host "==============="

    try {
        # Get all environment variables
        $envVariables = Get-ChildItem -Path Env: | Sort-Object Name

        # Display each environment variable
        foreach ($envVar in $envVariables) {
            Write-Host "$($envVar.Name): $($envVar.Value)"
        }

        dsplMessage "Environment variables retrieval completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while retrieving environment variables: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-UserSessions {
    dsplMessage "User Sessions" "info"
    Write-Host "==============="

    try {
        # Get all user sessions
        $sessions = Get-CimInstance -ClassName Win32_LogonSession -ErrorAction Stop

        foreach ($session in $sessions) {
            $user = $null
            $domain = $null

            # Retrieve the actual username and domain for the session
            $userQuery = "ASSOCIATORS OF {Win32_LogonSession.LogonId='$($session.LogonId)'} WHERE AssocClass=Win32_LoggedOnUser"
            $loggedOnUser = Get-CimInstance -Query $userQuery -ErrorAction SilentlyContinue

            if ($loggedOnUser) {
                $user = $loggedOnUser.Domain + "\" + $loggedOnUser.Name
                $domain = $loggedOnUser.Domain
            } else {
                # If unable to retrieve user details, use fallback from PSChildName
                if ($session.PSComputerName -eq $env:COMPUTERNAME) {
                    $user = $session.PSChildName
                    $domain = $env:USERDOMAIN
                } else {
                    $user = $session.PSChildName -split '\\' | Select-Object -Last 1
                    $domain = $session.PSChildName -split '\\' | Select-Object -First 1
                }
            }

            # Display session details
            Write-Host "User: $user"
            Write-Host "Domain: $domain"
            Write-Host "Logon Type: $($session.LogonType)"
            Write-Host "Logon Time: $(Get-Date -Date $session.StartTime)"
            Write-Host ""
        }

        dsplMessage "User sessions retrieval completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while retrieving user sessions: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-ProcessList {
    dsplMessage "Running Processes" "info"
    Write-Host "==============="

    try {
        # Retrieve list of running processes
        $processes = Get-Process

        # Display process information
        foreach ($process in $processes) {
            Write-Host "Name: $($process.ProcessName)"
            Write-Host "ID: $($process.Id)"
            Write-Host "CPU Time: $($process.CPUTime)"
            Write-Host "Memory (Working Set): $($process.WorkingSet / 1MB) MB"
            Write-Host "Description: $($process.Description)"
            Write-Host ""
        }

        dsplMessage "Process list retrieval completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while retrieving process list: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-UserRights {
    param (
        [string]$UserName = $env:USERNAME
    )

    dsplMessage "User Rights for $UserName" "info"
    Write-Host "==============="

    try {
        $userGroupsOutput = net user $UserName /domain 2>&1

        if ($userGroupsOutput -match "The user name could not be found") {
            dsplMessage "User '$UserName' not found." "error"
            return
        }

        if ($userGroupsOutput -match "System error 1355") {
            dsplMessage "Failed to retrieve domain information." "warning"
            dsplMessage "Using local information instead." "info"
            $userGroupsOutput = net user $UserName 2>&1
        }

        # Extract group names from net user output
        $groupMatches = $userGroupsOutput -split "`n" | Where-Object { $_ -match "Local Group Memberships" }

        foreach ($group in $groupMatches) {
            $groupName = ($group -split ":")[1].Trim()

            # Get group rights using net localgroup command
            $groupRightsOutput = net localgroup "$groupName" 2>&1

            if ($groupRightsOutput) {
                # Extract rights from net localgroup output
                $rights = ($groupRightsOutput -split "`n" | Select-String "Members")[0] -replace "Members", "" -replace "^\s+"

                Write-Host "Group: $groupName"
                Write-Host "Rights: $rights"
                Write-Host ""
            } else {
                dsplMessage "Failed to retrieve rights for group '$groupName'." "error"
            }
        }

        dsplMessage "User rights retrieval completed successfully." "success"
    } catch {
        dsplMessage "Error occurred while retrieving user rights: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-SystemCertificates {
    dsplMessage "System Certificates" "info"
    Write-Host "====================="

    try {
        # Define the system certificate store locations
        $certStores = @(
            "CurrentUser\My",
            "LocalMachine\My",
            "LocalMachine\Root",
            "LocalMachine\Trust",
            "LocalMachine\CA"
        )

        foreach ($storeLocation in $certStores) {
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeLocation, "LocalMachine")
                $store.Open("ReadOnly")

                Write-Host "Certificate Store: $storeLocation"
                Write-Host ""

                $certificates = $store.Certificates

                foreach ($cert in $certificates) {
                    Write-Host "Subject: $($cert.Subject)"
                    Write-Host "Issuer: $($cert.Issuer)"
                    Write-Host "Thumbprint: $($cert.Thumbprint)"
                    Write-Host "Valid From: $($cert.NotBefore)"
                    Write-Host "Valid To: $($cert.NotAfter)"
                    Write-Host "Friendly Name: $($cert.FriendlyName)"
                    Write-Host "Serial Number: $($cert.SerialNumber)"
                    Write-Host "---------------------------------------------"
                }

                $store.Close()
            } catch [System.Security.Cryptography.CryptographicException] {
                dsplMessage "Error accessing store '$storeLocation': Certificate store not found." "warning"
            } catch {
                dsplMessage "Error accessing store '$storeLocation': $_" "error"
            }
        }

        dsplMessage "System certificates retrieval completed successfully." "success"
    } catch {
        dsplMessage "General error occurred while retrieving system certificates: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-USBDevices {
    dsplMessage "USB Devices" "info"
    Write-Host "====================="

    try {
        $usbControllers = Get-WmiObject Win32_USBControllerDevice | ForEach-Object {
            [PSCustomObject]@{
                DeviceID = $_.Dependent.Split("=")[1].Trim('"').Replace("\\", "\")
                USBDevice = (Get-WmiObject -Query "ASSOCIATORS OF {$_.__PATH} WHERE ResultClass = Win32_PnPEntity").Name
            }
        }

        if ($usbControllers) {
            foreach ($device in $usbControllers) {
                Write-Host "Device ID: $($device.DeviceID)"
                Write-Host "Name: $($device.USBDevice)"
                Write-Host "---------------------------------------------"
            }
        } else {
            dsplMessage "No USB devices found." "info"
        }
    } catch {
        dsplMessage "Error occurred while retrieving USB device information: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-Printers {
    dsplMessage "Printers" "info"
    Write-Host "====================="

    try {
        $printers = Get-WmiObject -Class Win32_Printer

        if ($printers) {
            foreach ($printer in $printers) {
                Write-Host "Name: $($printer.Name)"
                Write-Host "Driver Name: $($printer.DriverName)"
                Write-Host "Port Name: $($printer.PortName)"
                Write-Host "---------------------------------------------"
            }
        } else {
            dsplMessage "No printers found." "info"
        }
    } catch {
        dsplMessage "Error occurred while retrieving printer information: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-NetworkConfiguration {
    dsplMessage "Network Configuration" "info"
    Write-Host "============================="

    try {
        # Get network adapters
        $networkAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True'

        if ($networkAdapters) {
            foreach ($adapter in $networkAdapters) {
                Write-Host "Adapter: $($adapter.Description)"
                Write-Host "---------------------------------"
                Write-Host "DHCP Enabled: $($adapter.DHCPEnabled)"
                Write-Host "IP Address(es): $($adapter.IPAddress -join ', ')"
                Write-Host "Subnet Mask(s): $($adapter.IPSubnet -join ', ')"
                Write-Host "Default Gateway: $($adapter.DefaultIPGateway -join ', ')"
                Write-Host "DNS Servers: $($adapter.DNSServerSearchOrder -join ', ')"
                Write-Host "MAC Address: $($adapter.MACAddress)"
                Write-Host ""
            }
        } else {
            dsplMessage "No network adapters found." "info"
        }
    } catch {
        dsplMessage "Error occurred while retrieving network configuration: $_" "error"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-ActiveDirectoryInformation {
    # Check if Active Directory module is installed and import if necessary
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        try {
            Import-Module -Name ActiveDirectory -ErrorAction Stop
            dsplMessage "Imported Active Directory module: $_" "success"
        } catch {
            dsplMessage "Failed to import Active Directory module: $_" "error"
            return
        }
    }

    # Ensure the module is imported successfully
    if (-not (Get-Module -Name ActiveDirectory)) {
        dsplMessage "Active Directory module could not be imported." "error"
        return
    }

    # Start retrieving Active Directory information
    dsplMessage "Active Directory Information" "info"
    Write-Host "================================="

    # Get domain information
    $domain = Get-ADDomain
    Write-Host "Domain Information:"
    Write-Host "  - Name: $($domain.Name)"
    Write-Host "  - DNS Root: $($domain.DNSRoot)"
    Write-Host "  - Domain Controllers: $($domain.DomainControllers -join ', ')"
    Write-Host "  - Domain Mode: $($domain.DomainMode)"
    Write-Host ""

    # Get domain controllers
    $domainControllers = Get-ADDomainController -Filter *
    Write-Host "Domain Controllers:"
    foreach ($dc in $domainControllers) {
        Write-Host "  - $($dc.Name) [$($dc.IPAddress)]"
    }
    Write-Host ""

    # Get organizational units (OUs)
    $organizationalUnits = Get-ADOrganizationalUnit -Filter *
    Write-Host "Organizational Units (OUs):"
    foreach ($ou in $organizationalUnits) {
        Write-Host "  - $($ou.DistinguishedName)"
        Write-Host "    - Name: $($ou.Name)"
        Write-Host "    - Description: $($ou.Description)"
    }
    Write-Host ""

    # Get users
    Write-Host "Users:"
    $users = Get-ADUser -Filter * -Property DisplayName, SamAccountName, UserPrincipalName, EmailAddress, Enabled, PasswordLastSet, LastLogonDate
    foreach ($user in $users) {
        Write-Host "  - $($user.DisplayName) ($($user.SamAccountName))"
        Write-Host "    - UserPrincipalName: $($user.UserPrincipalName)"
        Write-Host "    - Email Address: $($user.EmailAddress)"
        Write-Host "    - Enabled: $($user.Enabled)"
        Write-Host "    - Password Last Set: $($user.PasswordLastSet)"
        Write-Host "    - Last Logon Date: $($user.LastLogonDate)"
    }
    Write-Host ""

    # Get groups
    Write-Host "Groups:"
    $groups = Get-ADGroup -Filter * -Property DisplayName, SamAccountName, GroupScope, GroupCategory, Description, Members
    foreach ($group in $groups) {
        Write-Host "  - $($group.DisplayName) ($($group.SamAccountName))"
        Write-Host "    - Group Scope: $($group.GroupScope)"
        Write-Host "    - Group Category: $($group.GroupCategory)"
        Write-Host "    - Description: $($group.Description)"
        Write-Host "    - Members: $($group.Members -join ', ')"
    }
    Write-Host ""

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-RemoteDesktopSessions {
    [CmdletBinding()]
    param (
        # No parameters needed for local retrieval
    )

    try {
        # Display header for remote desktop sessions
        dsplMessage "Remote Desktop Sessions" "info"
        Write-Host "======================="

        # Query active remote desktop sessions using quser command
        $sessions = quser

        # Check if sessions were retrieved
        if ($sessions) {
            foreach ($session in $sessions) {
                Write-Host $session
            }
        } else {
            Write-Host "No active remote desktop sessions found."
        }

        # Display end of remote desktop sessions
        Write-Host "============================================================================================"
        Write-Host ""

    } catch {
        dsplMessage "Error occurred: $_" "error"
    }
}

function Get-LAPSInstallation {
    dsplMessage "Checking if LAPS is installed..." "info"
    Write-Host "==============="

    $lapsInstalled = $false

    # Define registry paths to check for LAPS installation
    $registryPaths = @(
        "HKLM:\Software\Policies\Microsoft Services\AdmPwd",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\History"
    )

    # Check each registry path
    foreach ($path in $registryPaths) {
        try {
            if (Test-Path -Path $path) {
                $lapsInstalled = $true
                Write-Host "LAPS registry path found: $path"
            }
        } catch {
            Write-Host "{!} Error occurred while checking registry path: $path"
            Write-Host $_.Exception.Message
        }
    }

    if ($lapsInstalled) {
        dsplMessage "LAPS is installed on this system." "success"
    } else {
        dsplMessage "LAPS is not installed on this system." "info"
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-LSAProtectionStatus {
    param(
        [switch]$Verbose
    )

    dsplMessage "Checking if LSA Protection is enabled..." "info"
    Write-Host "==============="
    # Path to the registry key
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $RegistryValue = "RunAsPPL"

    # Check if the registry key exists
    $keyExists = Test-Path $RegistryPath

    if ($keyExists) {
        # Get the value of RunAsPPL
        $LSAProtection = Get-ItemProperty -Path $RegistryPath -Name $RegistryValue -ErrorAction SilentlyContinue

        if ($null -ne $LSAProtection) {
            $RunAsPPL = $LSAProtection.$RegistryValue
        } else {
            $RunAsPPL = -1
        }
    } else {
        $RunAsPPL = -1
    }

    # Switch statement to provide detailed output
    switch ($RunAsPPL) {
        2 { Write-Host "RunAsPPL: 2. Enabled without UEFI Lock" }
        1 { Write-Host "RunAsPPL: 1. Enabled with UEFI Lock" }
        0 { Write-Host "RunAsPPL: 0. LSA Protection Disabled. Try mimikatz." -ForegroundColor Red }
        Default { Write-Host "The system was unable to find the specified registry value: RunAsPPL / RunAsPPLBoot" }
    }

    if ($Verbose) {
        if ($keyExists) {
            Write-Output "Registry key $RegistryPath exists."
            if ($RunAsPPL -ne -1) {
                Write-Output "Registry value $RegistryValue is set to $RunAsPPL."
            } else {
                Write-Output "Registry value $RegistryValue is not set."
            }
        } else {
            Write-Output "Registry key $RegistryPath does not exist."
        }
    }
    
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-CredentialGuardStatus {
    param(
        [switch]$Verbose
    )

    # Display initial message
    dsplMessage "Checking if Credential Guard is enabled..." "info"
    Write-Host "==============="

    # Path to the registry key
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    $RegistryValue = "EnableVirtualizationBasedSecurity"

    # Check if the registry key exists
    $keyExists = Test-Path $RegistryPath

    if ($keyExists) {
        # Get the value of EnableVirtualizationBasedSecurity
        $CredentialGuard = Get-ItemProperty -Path $RegistryPath -Name $RegistryValue -ErrorAction SilentlyContinue

        if ($null -ne $CredentialGuard) {
            $VBS = $CredentialGuard.$RegistryValue
        } else {
            $VBS = -1
        }
    } else {
        $VBS = -1
    }

    # Switch statement to provide detailed output
    switch ($VBS) {
        1 { Write-Host "Credential Guard: Enabled" -ForegroundColor Green }
        0 { Write-Host "Credential Guard: Disabled" -ForegroundColor Red }
        Default { Write-Host "The system was unable to find the specified registry value: EnableVirtualizationBasedSecurity" }
    }

    if ($Verbose) {
        if ($keyExists) {
            Write-Output "Registry key $RegistryPath exists."
            if ($VBS -ne -1) {
                Write-Output "Registry value $RegistryValue is set to $VBS."
            } else {
                Write-Output "Registry value $RegistryValue is not set."
            }
        } else {
            Write-Output "Registry key $RegistryPath does not exist."
        }
    }
    
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-UACStatus {
    dsplMessage "Checking User Account Control (UAC) settings..." "info"
    Write-Host "==============="

    # Path to the registry key
    $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $RegistryValue = "EnableLUA"

    # Check if the registry key exists
    $keyExists = Test-Path $RegistryPath

    if ($keyExists) {
        # Get the value of EnableLUA
        $UACSettings = Get-ItemProperty -Path $RegistryPath -Name $RegistryValue -ErrorAction SilentlyContinue

        if ($null -ne $UACSettings) {
            $EnableLUA = $UACSettings.$RegistryValue
        } else {
            $EnableLUA = -1
        }
    } else {
        $EnableLUA = -1
    }

    # Switch statement to provide detailed output
    switch ($EnableLUA) {
        1 { Write-Host "UAC: Enabled" -ForegroundColor Green }
        0 { Write-Host "UAC: Disabled" -ForegroundColor Red }
        Default { Write-Host "The system was unable to find the specified registry value: EnableLUA" }
    }
    Write-Host ""
    Write-Host "============================================================================================"
    Write-Host ""
}

function Get-SensitiveRegistryComponents {
    dsplMessage "Checking for sensitive information in registry..." "info"
    Write-Host "==============="

    # List of registry paths to check
    $registryPaths = @(
        "HKCU:\Software\ORL\WinVNC3\Password",
        "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP",
        "HKCU:\Software\TightVNC\Server",
        "HKCU:\Software\OpenSSH\Agent\Keys",
        "HKCU:\Software\SimonTatham\PuTTY\SshHostKeys"
    )

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            try {
                $value = Get-ItemProperty -Path $path -ErrorAction Stop
                if ($value) {
                    Write-Host ("Found sensitive information in $path :") -ForegroundColor Yellow
                    foreach ($property in $value.PSObject.Properties) {
                        Write-Host ("  $($property.Name): $($property.Value)")
                    }
                } else {
                    Write-Host ("No sensitive information found in $path") -ForegroundColor Green
                }
            } catch {
                Write-Host ("Error accessing $path : $_") -ForegroundColor Red
            }
        } else {
            Write-Host ("Registry path $path does not exist") -ForegroundColor Yellow
        }
    }
}

function Get-RecentCommands {
    dsplMessage "Checking recently run commands..." "info"
    Write-Host "==============="

    # Get recent commands from history
    $recentCommands = Get-History -Count 20  # Adjust the count as per your requirement

    if ($recentCommands) {
        foreach ($command in $recentCommands) {
            Write-Host ("Command: $($command.CommandLine)") -ForegroundColor Cyan
            Write-Host ("  Start Time: $($command.StartExecutionTime)")
            Write-Host ("  End Time: $($command.EndExecutionTime)")
            Write-Host ("  Duration: $($command.Duration.TotalSeconds) seconds")
            Write-Host "--------------"
        }
    } else {
        Write-Host "No recent commands found."
    }

    # Get PowerShell session history
    $sessionHistory = Get-History

    if ($sessionHistory) {
        Write-Host ""
        dsplMessage "PowerShell session history:" "info"
        Write-Host "==============="
        $sessionHistory | ForEach-Object {
            Write-Host ("ID: $($_.Id) | $($PSVersionTable.PSVersion) | $($_.CommandLine)") -ForegroundColor Yellow
        }
    } else {
        Write-Host "No PowerShell session history found."
    }

    Write-Host "============================================================================================"
    Write-Host ""
}

### Work In Progress
function Get-CommonFolderPermissions {
#TODO: If Specific Str then Highlight as possible vuln

}


############################################################
##### Main that makes the stuff actually do the stuff. #####
############################################################
# Define functions for different tasks
function Main {
    if ($Version) {
        dsplVersion
        exit 0
    }

    # Define the array of functions to call
    $functionsToCall = @(
        @{ Name = "SystemInformation"; ScriptBlock = { Get-SystemInformation } }
        @{ Name = "AvailableDrives"; ScriptBlock = { Get-AvailableDrives } }
        @{ Name = "AntivirusDetections"; ScriptBlock = { Get-AntivirusDetections } }
        @{ Name = "LAPSInstallation"; ScriptBlock = { Get-LAPSInstallation } }
        @{ Name = "LSAProtectionStatus"; ScriptBlock = { Get-LSAProtectionStatus -Verbose } }
        @{ Name = "CredentialGuardStatus"; ScriptBlock = { Get-CredentialGuardStatus -Verbose } }
        @{ Name = "UACStatus"; ScriptBlock = { Get-UACStatus } }
        @{ Name = "SensitiveRegistry"; ScriptBlock = { Get-SensitiveRegistryComponents } }
        @{ Name = "RecentCommands"; ScriptBlock = { Get-RecentCommands } }
        @{ Name = "InstalledKB"; ScriptBlock = { Get-InstalledKB } }
        @{ Name = "RunningServices"; ScriptBlock = { Get-RunningServices } }
        @{ Name = "PasswordPolicy"; ScriptBlock = { Get-PasswordPolicy } }
        @{ Name = "LocalUsers"; ScriptBlock = { Get-LocalUsers } }
        @{ Name = "LocalGroups"; ScriptBlock = { Get-LocalGroups } }
        @{ Name = "InstalledSoftware"; ScriptBlock = { Get-InstalledSoftware } }
        @{ Name = "OpenPorts"; ScriptBlock = { Get-OpenPorts } }
        @{ Name = "Netstat"; ScriptBlock = { Get-Netstat } }
        @{ Name = "FirewallRules"; ScriptBlock = { Get-FirewallRules } }
        @{ Name = "NetworkShares"; ScriptBlock = { Get-NetworkShares } }
        @{ Name = "RecentFiles"; ScriptBlock = { Get-RecentFiles } }
        @{ Name = "StartupPrograms"; ScriptBlock = { Get-StartupPrograms } }
        @{ Name = "EventLogs"; ScriptBlock = { Get-EventLogs } }
        @{ Name = "SystemLogs"; ScriptBlock = { Get-SystemLogs } }
        @{ Name = "RegistrySettings"; ScriptBlock = { Get-RegistrySettings } }
        @{ Name = "EnvironmentVariables"; ScriptBlock = { Get-EnvironmentVariables } }
        @{ Name = "UserSessions"; ScriptBlock = { Get-UserSessions } }
        @{ Name = "ProcessList"; ScriptBlock = { Get-ProcessList } }
        @{ Name = "UserRights"; ScriptBlock = { Get-UserRights } }
        @{ Name = "SystemCertificates"; ScriptBlock = { Get-SystemCertificates } }
        @{ Name = "USBDevices"; ScriptBlock = { Get-USBDevices } }
        @{ Name = "Printers"; ScriptBlock = { Get-Printers } }
        @{ Name = "NetworkConfiguration"; ScriptBlock = { Get-NetworkConfiguration } }
        @{ Name = "ActiveDirectoryInformation"; ScriptBlock = { Get-ActiveDirectoryInformation } }
        @{ Name = "RemoteDesktopSessions"; ScriptBlock = { Get-RemoteDesktopSessions } }
        # Add more functions here as needed
    )

    foreach ($function in $functionsToCall) {
        try {
            $output = & $function.ScriptBlock
            fncWriteToFile -functionName $function.Name -output $output
        } catch {
            Write-Host "An error occurred while executing $($function.Name): $_"
        }
    }
}

# Main script execution
Start-Transcript -Path "$PSScriptRoot\script-log.txt" -Append
try {
    dsplAsciiBanner
    dsplBlurb

    fncVerifyPSVersion
    fncConfigCheck
    if (fncCheckIfAdmin) {
        dsplMessage "Administrator privileges detected." "info"
    } else {
        dsplMessage "No administrator privileges detected." "info"
    }

    $system = (Get-WmiObject Win32_OperatingSystem).Caption
    dsplMessage "Detected Operating System: $system" "info"
    Write-Host ""

    Main
} catch {
    Write-Host "An error occurred during script execution: $_"
} finally {
    Stop-Transcript

    # Encode the script-log.txt file to base64
    $scriptLogFilePath = Join-Path -Path $PSScriptRoot -ChildPath "script-log.txt"
    $encodedFileName = Join-Path -Path $PSScriptRoot -ChildPath "$env:COMPUTERNAME-output.b64"
    fncB64Enc -filePath $scriptLogFilePath -encodedFilePath $encodedFileName

    # Output the base64 content to the console
    if (Test-Path $encodedFileName) {
        ## Disabled for the moment to stop Shell Destruction
        #$base64Content = Get-Content -Path $encodedFileName
        #Write-Output $base64Content
    } else {
        Write-Host "Failed to find encoded file: $encodedFileName"
    }
}
