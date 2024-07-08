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
    .\pr0ber.ps1 -SaveLocation "$env:SystemDrive\Scans" -NoConfig

    Captures a bunch of things, saving results to "$env:SystemDrive\Scans" without creating a configuration file.

.NOTES
    Script Version: 0.5
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
        "enabled" { Write-Host -ForegroundColor Yellow - "{X} $Message" }
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
| Version: 0.5                               |
|                                            |
| Created by Dean with a touch of care       |
==============================================
| Script Details:                            |
| Like WinPeas but maybe cooler?             |
|                                            |
==============================================
| Change Log:                                |
| 06/07/2024: Initial Code Build             |
| 07/07/2024: Added Hotfix Checks            |
|             Added Password Enum            |
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
            #Write-Host "No output received from function $functionName. Skipping file write."
            return
        }

        # It's a bit Broken right now...
        #$hostName = $env:COMPUTERNAME
        #$scriptDir = $PSScriptRoot
        #$fileName = Join-Path -Path $scriptDir -ChildPath "$hostName-$functionName.txt"

        Write-Host "Writing output of $functionName to $fileName"
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

    try {
        # Attempt to get system information using WMI
        $operatingSystem = (Get-WmiObject Win32_OperatingSystem).Caption
        $architecture = (Get-WmiObject Win32_ComputerSystem).SystemType
        $currentUser = $env:USERNAME
        $lastBootTime = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
        $lastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime($lastBootTime)
        $uptime = (Get-Date) - (Get-WmiObject Win32_OperatingSystem).ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).LastBootUpTime)
        $bios = Get-WmiObject Win32_BIOS
        $totalMemoryGB = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        $processor = Get-WmiObject Win32_Processor
        $systemDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"

        # Display system information retrieved from WMI
        dsplMessage "Operating System: $operatingSystem" "warning"
        dsplMessage "System Architecture: $architecture" "info"
        dsplMessage "Current User: $currentUser" "info"
        dsplMessage "Last Boot Time: $lastBootTime" "info"
        dsplMessage "Uptime: $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes" "info"
        dsplMessage "BIOS Version: $($bios.SMBIOSBIOSVersion)" "info"
        dsplMessage "Manufacturer: $($bios.Manufacturer)" "info"
        dsplMessage "Release Date: $($bios.ConvertToDateTime($bios.ReleaseDate))" "info"
        dsplMessage "Total Physical Memory: $totalMemoryGB GB" "info"
        dsplMessage "Processor: $($processor.Name)" "info"
        dsplMessage "Number of Cores: $($processor.NumberOfCores)" "info"
        dsplMessage "Max Clock Speed: $($processor.MaxClockSpeed) MHz" "info"
        dsplMessage "System Drive ($env:SystemDrive) Size: $([math]::Round($systemDrive.Size / 1GB, 2)) GB" "info"
        dsplMessage "System Drive ($env:SystemDrive) Free Space: $([math]::Round($systemDrive.FreeSpace / 1GB, 2)) GB" "info"

    } catch {
        dsplMessage "Failed to retrieve system information using WMI. Using systeminfo.exe." "warning"
        
        # Use systeminfo.exe command to get system information
        $systeminfoOutput = Invoke-Expression "systeminfo.exe"

        # Display system information from systeminfo.exe output
        dsplMessage $systeminfoOutput "info"
    }
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
                if ($user.Disabled -eq $true) {
                    dsplMessage "    Status: Disabled" "disabled"
                } else {
                    Write-Host "        Status: Enabled       " -ForegroundColor Green -NoNewline; 
                    dsplMessage " This user is enabled worth a look" "error" 
                }
                Write-Host ""
            }
        } else {
            dsplMessage "No local user accounts found." "info"
        }
    } catch {
        dsplMessage "Error occurred while retrieving local user accounts: $_" "error"
    } 
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
                Write-Host ""
            }
        } else {
            dsplMessage "No local groups found." "info"
        }
    } catch {
        dsplMessage "Error occurred while retrieving local groups: $_" "error"
    }
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
}

function Get-OpenPorts {
    dsplMessage "Open Ports" "info"
    Write-Host "==========="
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

        foreach ($port in $ports) {
            # Start an asynchronous task for each port check
            $task = {
                param($port)
                try {
                    $result = Test-NetConnection -ComputerName localhost -Port $port -InformationLevel Quiet -ErrorAction Stop
                    if ($result.TcpTestSucceeded) {
                        [PSCustomObject]@{
                            Port = $port
                            RemoteAddress = $result.RemoteAddress
                            RemotePort = $result.RemotePort
                        }
                    }
                } catch {
                    Write-Warning $_.Exception.Message
                    return $null
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
                    Write-Host "        Status: Open       " -ForegroundColor Green -NoNewline;
                    dsplMessage " This port is open worth a look" "error"
                    Write-Host "    Remote Address: $($result.RemoteAddress)"
                    Write-Host "    Remote Port: $($result.RemotePort)"
                    Write-Host ""
                }
            } elseif ($job.State -eq 'Running') {
                Write-Host 
                dsplMessage "Port check for job $($job.Id) timed out." "disabled"
            } else {
                Write-Host 
                dsplMessage "Port check for job $($job.Id) failed or is closed." "disabled"
            }
            Remove-Job -Job $job
        }
        dsplProgress "Port scanning finished."
    } catch {
        dsplMessage "Error occurred while checking open ports: $_" "error"
    }
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
}

function Get-FirewallRules {
    dsplMessage "Firewall Rules" "info"
    Write-Host "==============="

    try {
        # Attempt to get firewall rules using Get-NetFirewallRule
        $rules = Get-NetFirewallRule -ErrorAction Stop

        # Display firewall rules using Get-NetFirewallRule formatting
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

        dsplMessage "Firewall rules retrieved successfully using Get-NetFirewallRule." "success"
    } catch {
        dsplMessage "Error occurred while retrieving firewall rules using Get-NetFirewallRule: $_" "error"

        dsplMessage "Attempting to retrieve firewall rules using netsh commands..." "warning"

        try {
            # Retrieve specific firewall rule using netsh
            $ruleName = "allow browser"
            $firewallRuleVerbose = & netsh advfirewall firewall show rule name="$ruleName" verbose

            # Display specific firewall rule verbose output
            dsplMessage "Firewall Rule (Verbose): $ruleName" "info"
            Write-Host $firewallRuleVerbose
            Write-Host ""

            # Retrieve dynamic inbound rules using netsh
            $firewallDynamicInbound = & netsh advfirewall firewall show rule name=all dir=in type=dynamic

            # Display dynamic inbound firewall rules
            dsplMessage "Dynamic Inbound Firewall Rules:" "info"
            #Write-Host $firewallDynamicInbound    #### Disabled due to spaaaam until I can clean up output

            dsplMessage "Firewall rules retrieved successfully using netsh commands." "success"
        } catch {
            dsplMessage "Error occurred while retrieving firewall rules using netsh commands: $_" "error"
        }
    }
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
}

function Get-UserRights {
    param (
        [string]$UserName = $env:USERNAME
    )

    dsplMessage "User Rights for $UserName" "info"
    Write-Host "==============="

    try {
        # Attempt to retrieve domain user group information
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

        # Check if $userGroupsOutput is null or empty after domain handling
        if (-not $userGroupsOutput) {
            throw "Failed to retrieve user group information. Output is null or empty."
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

                # Output formatted as desired
                Write-Host "Group: $groupName"
                Write-Host "Rights: $rights"
                Write-Host ""
            } else {
                dsplMessage "Failed to retrieve rights for group '$groupName'." "error"
            }
        }

        dsplMessage "User rights retrieval completed successfully." "success"
    } catch [System.Management.Automation.MethodInvocationException] {
        dsplMessage "Error: Failed to invoke a method on a null-valued expression. Ensure the user exists and try again." "error"
    } catch {
        # Check if the error message matches "This command can be used only on a Windows Domain Controller"
        if ($_.Exception.Message -match "This command can be used only on a Windows Domain Controller") {
            dsplMessage "Error: This command can be used only on a Windows Domain Controller." "error"
        } else {
            dsplMessage "Error occurred while retrieving user rights: $_" "error"
        }
    }
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

    Write-Host ""
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
        Write-Host ""
        Write-Host ""

    } catch {
        dsplMessage "Error occurred: $_" "error"
    }
}

function Get-LAPSInstallation {
    dsplMessage "Checking if LAPS is installed..." "info"
    Write-Host "==============="

    $lapsInstalledKeyFound = $false
    $lapsInstalledDirFound = $false

    # Define registry paths to check for LAPS installation
    $registryPaths = @(
        "HKLM:\Software\Policies\Microsoft Services\AdmPwd",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\History"
    )

    # Define file directories to check for LAPS installation
    $fileDirectories = @(
        "$env:SystemDrive\Program Files\LAPS",
        "$env:SystemDrive\Program Files (x86)\LAPS"
    )

    # Check each registry path
    foreach ($path in $registryPaths) {
        try {
            if (Test-Path -Path $path) {
                $lapsInstalledKeyFound = $true
                Write-Host "LAPS registry path found: $path"
            }
        } catch {
            Write-Host "{!} Error occurred while checking registry path: $path"
            Write-Host $_.Exception.Message
        }
    }

    # Check each file directory
    foreach ($directory in $fileDirectories) {
        try {
            if (Test-Path -Path $directory -PathType Container) {
                $lapsInstalledDirFound = $true
                Write-Host "LAPS directory found: $directory"
            }
        } catch {
            Write-Host "{!} Error occurred while checking directory: $directory"
            Write-Host $_.Exception.Message
        }
    }

    if ($lapsInstalledKeyFound) {
        dsplMessage "LAPS Registry Key found." "success"
    } else {
        dsplMessage "LAPS is not configured." "info"
    }
    if ($lapsInstalledDirFound) {
        dsplMessage "LAPS is installed on this system." "success"
    } else {
        dsplMessage "LAPS is not installed on this system." "info"
    }
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
        2 { dsplMessage "RunAsPPL: 2. Enabled without UEFI Lock" "warning" }
        1 { dsplMessage "RunAsPPL: 1. Enabled with UEFI Lock" "success" }
        0 { dsplMessage "RunAsPPL: 0. LSA Protection Disabled." "disabled" }
        Default { dsplMessage "The system was unable to find the specified registry value: RunAsPPL / RunAsPPLBoot" "warning" }
    }
    if ($Verbose) {
        if ($keyExists) {
            Write-Output "Registry key $RegistryPath exists."
            if ($RunAsPPL -ne -1) {
                Write-Host "    Registry value $RegistryValue is set to $RunAsPPL." -ForegroundColor Green -NoNewline;  dsplMessage "    LSA Protection is set to $RunAsPPL : " "error"
            } else {
                Write-Output "Registry value $RegistryValue is not set."
            }
        } else {
            Write-Output "Registry key $RegistryPath does not exist."
        }
    }
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
        1 { dsplMessage "Credential Guard: Enabled" "enabled" }
        0 { dsplMessage "Credential Guard: Disabled." "disabled" }
        Default { dsplMessage "The system was unable to find the specified registry value: EnableVirtualizationBasedSecurity" "warning" }
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
        1 { dsplMessage "UA$env:SystemDrive Enabled" "enabled" }
        0 { dsplMessage "UA$env:SystemDrive Disabled." "disabled" }
        Default { dsplMessage "UA$env:SystemDrive Registry not found." "warning" }
    }
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
}

### Work In Progress
function Get-CommonFolderPermissions {
    dsplMessage "Folder Permissions" "info"
    dsplMessage "==================" "info"
    try {
        # Define an array of common folder paths to check
        $folders = @(
            "$env:SystemDrive\Users",                                  # User profiles
            "$env:SystemDrive\Users\Public",                           # Public user profile
            "$env:SystemDrive\Temp",                                   # Temporary files
            "$env:SystemDrive\Windows\Temp",                           # Windows temporary files
            "$env:SystemDrive\Documents and Settings\All Users\Start Menu\Programs\Startup",    # Startup folder for all users (legacy)
            "$env:SystemDrive\Documents and Settings\$env:Username\Start Menu\Programs\Startup", # Startup folder for current user (legacy)
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",     # Startup folder for all users (modern)
            "$env:Appdata\Microsoft\Windows\Start Menu\Programs\Startup",         # Startup folder for current user (modern)
            "$env:SystemDrive\Windows\System32\drivers\etc\",          # Hosts file and network configuration
            "$env:SystemDrive\Windows\System32\inetsrv",               # IIS (Internet Information Services) config and logs
            "$env:SystemDrive\inetpub",                                # IIS web root folder
            "$env:SystemDrive\Program Files\Apache Software Foundation",   # Apache HTTP Server
            "$env:SystemDrive\Program Files (x86)\Apache Software Foundation",
            "$env:SystemDrive\Program Files\MySQL",                    # MySQL database
            "$env:SystemDrive\Program Files (x86)\MySQL",
            "$env:SystemDrive\Program Files\Microsoft SQL Server",     # Microsoft SQL Server
            "$env:SystemDrive\Program Files (x86)\Microsoft SQL Server",
            "$env:SystemDrive\Program Files\Microsoft SQL Server Compact Edition",   # SQL Server Compact Edition
            "$env:SystemDrive\Program Files (x86)\Microsoft SQL Server Compact Edition",
            "$env:SystemDrive\Program Files\PostgreSQL",               # PostgreSQL database
            "$env:SystemDrive\Program Files (x86)\PostgreSQL",
            "$env:SystemDrive\Program Files\Oracle",                   # Oracle database
            "$env:SystemDrive\Program Files (x86)\Oracle",
            "$env:SystemDrive\Program Files\IBM",                      # IBM DB2 database
            "$env:SystemDrive\Program Files (x86)\IBM",
            "$env:SystemDrive\Program Files\Git",                      # Git version control
            "$env:SystemDrive\Program Files (x86)\Git",
            "$env:SystemDrive\Program Files\Docker",                   # Docker containers
            "$env:SystemDrive\Program Files (x86)\Docker",
            "$env:SystemDrive\Program Files\Microsoft Office",         # Microsoft Office applications
            "$env:SystemDrive\Program Files (x86)\Microsoft Office",
            "$env:SystemDrive\Program Files\Microsoft Exchange Server",# Microsoft Exchange Server
            "$env:SystemDrive\Program Files (x86)\Microsoft Exchange Server",
            #"$env:SystemDrive\Program Files\Microsoft SQL Server Management Studio 18",   # SQL Server Management Studio
            #"$env:SystemDrive\Program Files (x86)\Microsoft SQL Server Management Studio 18",
            #"$env:SystemDrive\Program Files\Microsoft SQL Server Management Studio 17",
            #"$env:SystemDrive\Program Files (x86)\Microsoft SQL Server Management Studio 17",
            #"$env:SystemDrive\Program Files\Microsoft SQL Server Management Studio 16",
            #"$env:SystemDrive\Program Files (x86)\Microsoft SQL Server Management Studio 16",
            "$env:SystemDrive\Program Files\Microsoft SQL Server\150",   # SQL Server 2019 folders
            "$env:SystemDrive\Program Files (x86)\Microsoft SQL Server\150",
            "$env:SystemDrive\Program Files\Microsoft SQL Server\140",   # SQL Server 2017 folders
            "$env:SystemDrive\Program Files (x86)\Microsoft SQL Server\140",
            "$env:SystemDrive\Program Files\Microsoft SQL Server\130",   # SQL Server 2016 folders
            "$env:SystemDrive\Program Files (x86)\Microsoft SQL Server\130",
            "$env:SystemDrive\Program Files\Microsoft SQL Server\120",   # SQL Server 2014 folders
            "$env:SystemDrive\Program Files (x86)\Microsoft SQL Server\120",
            "$env:SystemDrive\Program Files\Microsoft Configuration Manager",   # Microsoft Configuration Manager (SCCM)
            "$env:SystemDrive\Program Files (x86)\Microsoft Configuration Manager"
        )

        # Define an array to collect file checks for deferred processing
        $fileChecks = @()

        # Get the current user
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        foreach ($folder in $folders) {
            try {
                if (Test-Path -Path $folder) {
                    $acl = Get-Acl -Path $folder
                    $owner = $acl.Owner
                    $accessRules = $acl.Access | Where-Object { $_.IdentityReference -eq $currentUser }

                    # Initialize permission flags
                    $hasRead = $false
                    $hasWrite = $false
                    $hasExecute = $false

                    # Check permissions for the current user
                    foreach ($rule in $accessRules) {
                        if ($rule.AccessControlType -eq "Allow") {
                            if ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) { $hasRead = $true }
                            if ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) { $hasWrite = $true }
                            if ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile) { $hasExecute = $true }
                        }
                    }

                    # Display the folder permissions
                    dsplMessage "Folder: $folder" "info"
                    dsplMessage "  Owner: $owner" "info"
                    dsplMessage "  Current User: $currentUser" "info"
                    dsplMessage "  Permissions:" "info"

                    if ($hasRead) { dsplMessage "    Read: Yes" "info" } else { dsplMessage "    Read: No" "disabled" }
                    if ($hasWrite) { Write-Host "        Write: Yes       " -ForegroundColor Green -NoNewline;  dsplMessage "    This folder has write permissions worth a look" "error" } else { dsplMessage "    Read: No" "disabled" }
                    if ($hasExecute) { Write-Host "        Execute: Yes     " -ForegroundColor Green -NoNewline;  dsplMessage "    This folder has execute permissions worth a look" "error" } else { dsplMessage "    Read: No" "disabled" }
                    Write-Host ""

                    # Add folder's files to the deferred file checks
                    $filesToCheck = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
                    foreach ($file in $filesToCheck) {
                        $fileChecks += @{
                            Folder = $folder
                            File = $file.FullName
                        }
                    }

                    Write-Host ""
                } else {
                    dsplMessage "Folder: $folder" "info"
                    dsplMessage "  Status: Does not exist" "info"
                    Write-Host ""
                }
            } catch {
                dsplMessage "Error occurred while checking permissions for folder: $folder. Error: $_" "error"
            }
        }

        Write-Host ""
        dsplMessage "File Permissions" "info"
        dsplMessage "==================" "info"
        foreach ($fileCheck in $fileChecks) {
            $folder = $fileCheck.Folder
            $file = $fileCheck.File

            try {
                if (Test-Path -Path $file) {
                    $fileOwner = (Get-Acl -Path $file).Owner
                    $fileAccessRules = (Get-Acl -Path $file).Access | Where-Object { $_.IdentityReference -eq $currentUser }

                    # Initialize permission flags for the file
                    $fileHasRead = $false
                    $fileHasWrite = $false
                    $fileHasExecute = $false

                    # Check permissions for the current user on the file
                    foreach ($rule in $fileAccessRules) {
                        if ($rule.AccessControlType -eq "Allow") {
                            if ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) { $fileHasRead = $true }
                            if ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) { $fileHasWrite = $true }
                            if ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile) { $fileHasExecute = $true }
                        }
                    }

                    # Display file permissions
                    dsplMessage "File: $file" "info"
                    dsplMessage "  Owner: $fileOwner" "info"
                    dsplMessage "  Current User: $currentUser" "info"
                    dsplMessage "  Permissions:" "info"
                    if ($fileHasRead) { Write-Host "        Read: Yes        " -ForegroundColor Green -NoNewline;  dsplMessage "    This file has read permissions worth a look" "error" } else { dsplMessage "    Read: No" "disabled" }
                    if ($fileHasWrite) { Write-Host "        Write: Yes       " -ForegroundColor Green -NoNewline;  dsplMessage "    This file has write permissions worth a look" "error" } else { dsplMessage "    Read: No" "disabled" }
                    if ($fileHasExecute) { Write-Host "        Execute: Yes     " -ForegroundColor Green -NoNewline;  dsplMessage "    This file has execute permissions worth a look" "error" } else { dsplMessage "    Read: No" "disabled" }
                    Write-Host ""
                    Start-Sleep(0.5)
                } else {
                    dsplMessage "File: $file" "info"
                    dsplMessage "  Status: Does not exist" "info"
                    Write-Host ""
                }
            } catch {
                dsplMessage "Error occurred while checking permissions for file: $file. Error: $_" "error"
            }
        }

    } catch {
        dsplMessage "Error occurred while checking folder and file permissions: $_" "error"
    }
}

function Get-Sharphound { 
    dsplMessage "SharpHound Download and Execution" "info"
    
    # Ask the user if they want to proceed
    $userResponse = Read-Host "Do you want to download and execute SharpHound? (y/n)"
    
    if ($userResponse -eq "y") {
        dsplMessage "Proceeding with SharpHound download and execution." "info"
        
        try {
            # Define the URL for the latest SharpHound release
            $url = "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.zip"
            $zipPath = "$PSScriptRoot\SharpHound.zip"
            $extractPath = "$PSScriptRoot\SharpHound"
            
            if (-Not (Test-Path -Path $extractPath)) {
                New-Item -ItemType Directory -Path $extractPath
            }

            dsplMessage "Downloading SharpHound from GitHub..." "info"
            
            # Start the download job
            $job = Start-Job -ScriptBlock {
                param($url, $zipPath)
                try {
                    Invoke-WebRequest -Uri $url -OutFile $zipPath -ErrorAction Stop
                } catch {
                    $_.Exception.Message
                }
            } -ArgumentList $url, $zipPath
            
            # Wait for the job to complete with a timeout
            $jobResult = Wait-Job -Job $job -Timeout 5

            if ($jobResult -eq $null) {
                # Job timed out
                dsplMessage "The internet connection may be blocked. Do you want to provide a local web URL for SharpHound? (y/n)" "info"
                $localResponse = Read-Host
                if ($localResponse -eq "y") {
                    $localUrl = Read-Host "Please provide the local web URL to SharpHound.zip"
                    try {
                        Invoke-WebRequest -Uri $localUrl -OutFile $zipPath -ErrorAction Stop
                    } catch {
                        dsplMessage "Failed to download from the provided local web URL." "error"
                        return
                    }
                } else {
                    dsplMessage "User opted not to provide a local web URL. Exiting." "info"
                    return
                }
            } else {
                # Job completed successfully
                $output = Receive-Job -Job $job
                if ($output -match "Not Found") {
                    dsplMessage "The specified URL was not found or the server is blocking external web access. Do you want to provide a local web URL for SharpHound? (y/n)" "info"
                    $localResponse = Read-Host
                    if ($localResponse -eq "y") {
                        $localUrl = Read-Host "Please provide the local web URL to SharpHound.zip"
                        try {
                            Invoke-WebRequest -Uri $localUrl -OutFile $zipPath -ErrorAction Stop
                        } catch {
                            dsplMessage "Failed to download from the provided local web URL." "error"
                            return
                        }
                    } else {
                        dsplMessage "User opted not to provide a local web URL. Exiting." "info"
                        return
                    }
                }
            }
            
            dsplMessage "Extracting SharpHound..." "info"
            Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

            $sharpHoundExe = "$extractPath\SharpHound.exe"
            
            if (Test-Path -Path $sharpHoundExe) {
                dsplMessage "SharpHound downloaded and extracted successfully." "info"
                
                $job = Start-Job -ScriptBlock {
                    param($sharpHoundPath)
                    
                    dsplMessage "Starting SharpHound execution..." "info"
                    
                    try {
                        & $sharpHoundPath -c All
                    } catch {
                        dsplMessage "Error occurred while executing SharpHound: $_" "error"
                    }
                    
                    dsplMessage "SharpHound execution completed." "info"
                } -ArgumentList $sharpHoundExe
                
                dsplMessage "SharpHound is running in the background. Job ID: $($job.Id)" "info"
            } else {
                dsplMessage "SharpHound executable not found after extraction." "error"
            }
        } catch {
            dsplMessage "Error occurred during SharpHound download and execution: $_" "error"
        }
    } else {
        dsplMessage "User opted not to proceed with SharpHound download and execution." "info"
    }
}

function Get-PossibleRCELPE {
    dsplMessage "Checking for any possible RCE or LPE vulnerabilities" "info"
    dsplMessage "==================" "info"
    dsplMessage "Please Note! some of the following may be False Positives - Check which OS it affects first." "info"
    Start-Sleep (1)

    # MS11-080 (KB2592799)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB2592799" }
    if ($hotfix) {
        dsplMessage "       MS11-080 (HF: KB2592799) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS11-080 (HF: KB2592799) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Vista, Windows Server 2008" "info"
        dsplMessage "           Affected Module: afd.sys - Local privilege Escalation" "info"
    }

    # MS16-032 (KB3143141)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB3143141" }
    if ($hotfix) {
        dsplMessage "       MS16-032 (HF: KB3143141) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS16-032 (HF: KB3143141) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Vista, Windows Server 2008" "info"
        dsplMessage "           Affected Module: Secondary Logon - Local privilege Escalation" "info"
    }

    # MS11-011 (KB2393802)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB2393802" }
    if ($hotfix) {
        dsplMessage "       MS11-011 (HF: KB2393802) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS11-011 (HF: KB2393802) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Vista, Windows Server 2008" "info"
        dsplMessage "           Affected Module: WmiTraceMessageVa - Local privilege Escalation" "info"
    }

    # MS10-059 (KB982799)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB982799" }
    if ($hotfix) {
        dsplMessage "       MS10-059 (HF: KB982799) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS10-059 (HF: KB982799) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: All supported Windows versions" "info"
        dsplMessage "           Affected Module: Chimichurri - Local privilege Escalation" "info"
    }

    # MS10-021 (KB979683)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB979683" }
    if ($hotfix) {
        dsplMessage "       MS10-021 (HF: KB979683) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS10-021 (HF: KB979683) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows XP, Windows Server 2003" "info"
        dsplMessage "           Affected Module: Windows Kernel - Local privilege Escalation" "info"
    }

    # MS10-092 (KB2305420)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB2305420" }
    if ($hotfix) {
        dsplMessage "       MS10-092 (HF: KB2305420) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS10-092 (HF: KB2305420) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2008" "info"
        dsplMessage "           Affected Module: Task Scheduler - Local privilege Escalation" "info"
    }

    # MS10-073 (KB981957)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB981957" }
    if ($hotfix) {
        dsplMessage "       MS10-073 (HF: KB981957) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS10-073 (HF: KB981957) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Vista, Windows 7" "info"
        dsplMessage "           Affected Module: Keyboard Layout - Local privilege Escalation" "info"
    }

    # MS17-017 (KB4013081)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4013081" }
    if ($hotfix) {
        dsplMessage "       MS17-017 (HF: KB4013081) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS17-017 (HF: KB4013081) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2008, Windows 7, Windows Server 2012" "info"
        dsplMessage "           Affected Module: Registry Hive Loading - Local privilege Escalation" "info"
    }

    # MS10-015 (KB977165)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB977165" }
    if ($hotfix) {
        dsplMessage "       MS10-015 (HF: KB977165) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS10-015 (HF: KB977165) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: All supported Windows versions" "info"
        dsplMessage "           Affected Module: User Mode to Ring - Local privilege Escalation" "info"
    }

    # MS08-025 (KB941693)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB941693" }
    if ($hotfix) {
        dsplMessage "       MS08-025 (HF: KB941693) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS08-025 (HF: KB941693) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows XP, Windows Server 2003" "info"
        dsplMessage "           Affected Module: win32k.sys - Local privilege Escalation" "info"
    }

    # MS06-049 (KB920958)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB920958" }
    if ($hotfix) {
        dsplMessage "       MS06-049 (HF: KB920958) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS06-049 (HF: KB920958) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2003, Windows XP" "info"
        dsplMessage "           Affected Module: ZwQuerySysInfo - Local privilege Escalation" "info"
    }

    # MS06-030 (KB914389)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB914389" }
    if ($hotfix) {
        dsplMessage "       MS06-030 (HF: KB914389) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS06-030 (HF: KB914389) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows XP, Windows Server 2003" "info"
        dsplMessage "           Affected Module: Mrxsmb.sys - Local privilege Escalation" "info"
    }

    # MS05-055 (KB908523)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB908523" }
    if ($hotfix) {
        dsplMessage "       MS05-055 (HF: KB908523) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS05-055 (HF: KB908523) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows XP, Windows Server 2003" "info"
        dsplMessage "           Affected Module: APC Data-Free - Local privilege Escalation" "info"
    }

    # MS05-018 (KB890859)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB890859" }
    if ($hotfix) {
        dsplMessage "       MS05-018 (HF: KB890859) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS05-018 (HF: KB890859) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows XP, Windows Server 2003" "info"
        dsplMessage "           Affected Module: CSRSS - Local privilege Escalation" "info"
    }

    # MS04-019 (KB842526)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB842526" }
    if ($hotfix) {
        dsplMessage "       MS04-019 (HF: KB842526) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS04-019 (HF: KB842526) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows XP, Windows Server 2003, Windows 2000" "info"
        dsplMessage "           Affected Module: Utility Manager - Local privilege Escalation" "info"
    }

    # MS04-011 (KB835732)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB835732" }
    if ($hotfix) {
        dsplMessage "       MS04-011 (HF: KB835732) RCE patch is installed :)" "success"
    } else {
        dsplMessage "       MS04-011 (HF: KB835732) RCE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows XP, Windows Server 2003, Windows 2000" "info"
        dsplMessage "           Affected Module: LSASS service BoF - Remote Code Execution" "info"
    }

    # MS04-020 (KB841872)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB841872" }
    if ($hotfix) {
        dsplMessage "       MS04-020 (HF: KB841872) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS04-020 (HF: KB841872) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows XP, Windows Server 2003, Windows 2000" "info"
        dsplMessage "           Affected Module: POSIX - Local privilege Escalation" "info"
    }

    # MS14-040 (KB2975684)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB2975684" }
    if ($hotfix) {
        dsplMessage "       MS14-040 (HF: KB2975684) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS14-040 (HF: KB2975684) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2008, Windows 7" "info"
        dsplMessage "           Affected Module: afd.sys Dangling Pointer - Local privilege Escalation" "info"
    }

    # MS16-016 (KB3136041)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB3136041" }
    if ($hotfix) {
        dsplMessage "       MS16-016 (HF: KB3136041) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS16-016 (HF: KB3136041) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Vista, Windows Server 2008" "info"
        dsplMessage "           Affected Module: WebDAV to Address - Local privilege Escalation" "info"
    }

    # MS15-051 (KB3057191)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB3057191" }
    if ($hotfix) {
        dsplMessage "       MS15-051 (HF: KB3057191) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS15-051 (HF: KB3057191) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Vista, Windows Server 2008" "info"
        dsplMessage "           Affected Module: win32k.sys - Local privilege Escalation" "info"
    }

    # MS14-070 (KB2989935)
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB2989935" }
    if ($hotfix) {
        dsplMessage "       MS14-070 (HF: KB2989935) LPE patch is installed :)" "success"
    } else {
        dsplMessage "       MS14-070 (HF: KB2989935) LPE patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Vista, Windows Server 2008" "info"
        dsplMessage "           Affected Module: TCP/IP - Local privilege Escalation" "info"
    }

    # Windows 10 LPE vulnerabilities
    # CVE-2021-1647: Windows AppX Package Manager Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558993" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-1647: Windows AppX Package Manager patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-1647: Windows AppX Package Manager patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 10" "info"
        dsplMessage "           Affected Module: AppX Package Manager - Local privilege Escalation" "info"
    }

    # CVE-2021-26401: Windows Print Spooler Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558992" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-26401: Windows Print Spooler patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-26401: Windows Print Spooler patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 10" "info"
        dsplMessage "           Affected Module: Print Spooler - Local privilege Escalation" "info"
    }

    # CVE-2021-36935: Windows Kernel Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558991" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-36935: Windows Kernel patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-36935: Windows Kernel patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 10" "info"
        dsplMessage "           Affected Module: Kernel - Local privilege Escalation" "info"
    }

    # Windows 10 RCE vulnerabilities

    # CVE-2021-26413: Windows HTTP.sys Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558994" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-26413: Windows HTTP.sys patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-26413: Windows HTTP.sys patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 10" "info"
        dsplMessage "           Affected Module: HTTP.sys - Remote Code Execution" "info"
    }

    # CVE-2021-36934: Windows DNS Server Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558993" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-36934: Windows DNS Server patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-36934: Windows DNS Server patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 10" "info"
        dsplMessage "           Affected Module: DNS Server - Remote Code Execution" "info"
    }

    # CVE-2021-40449: Windows SMBv3 Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558996" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-40449: Windows SMBv3 patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-40449: Windows SMBv3 patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 10" "info"
        dsplMessage "           Affected Module: SMBv3 - Remote Code Execution" "info"
    }

    # Windows 11 LPE vulnerabilities

    # CVE-2022-22013: Windows AppX Package Manager Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015564" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-22013: Windows AppX Package Manager patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-22013: Windows AppX Package Manager patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 11" "info"
        dsplMessage "           Affected Module: AppX Package Manager - Local privilege Escalation" "info"
    }

    # CVE-2022-24491: Windows Print Spooler Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015563" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-24491: Windows Print Spooler patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-24491: Windows Print Spooler patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 11" "info"
        dsplMessage "           Affected Module: Print Spooler - Local privilege Escalation" "info"
    }

    # CVE-2022-26938: Windows Kernel Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015562" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-26938: Windows Kernel patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-26938: Windows Kernel patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 11" "info"
        dsplMessage "           Affected Module: Kernel - Local privilege Escalation" "info"
    }

    # Windows 11 RCE vulnerabilities

    # CVE-2022-22014: Windows HTTP.sys Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015565" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-22014: Windows HTTP.sys patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-22014: Windows HTTP.sys patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 11" "info"
        dsplMessage "           Affected Module: HTTP.sys - Remote Code Execution" "info"
    }

    # CVE-2022-24492: Windows DNS Server Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015564" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-24492: Windows DNS Server patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-24492: Windows DNS Server patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 11" "info"
        dsplMessage "           Affected Module: DNS Server - Remote Code Execution" "info"
    }

    # CVE-2022-26937: Windows SMBv3 Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015561" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-26937: Windows SMBv3 patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-26937: Windows SMBv3 patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows 11" "info"
        dsplMessage "           Affected Module: SMBv3 - Remote Code Execution" "info"
    }

    # Windows Server 2019 LPE vulnerabilities

    # CVE-2021-1647: Windows AppX Package Manager Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558993" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-1647: Windows AppX Package Manager patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-1647: Windows AppX Package Manager patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2019" "info"
        dsplMessage "           Affected Module: AppX Package Manager - Local privilege Escalation" "info"
    }

    # CVE-2021-26401: Windows Print Spooler Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558992" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-26401: Windows Print Spooler patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-26401: Windows Print Spooler patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2019" "info"
        dsplMessage "           Affected Module: Print Spooler - Local privilege Escalation" "info"
    }

    # CVE-2021-36935: Windows Kernel Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558991" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-36935: Windows Kernel patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-36935: Windows Kernel patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2019" "info"
        dsplMessage "           Affected Module: Kernel - Local privilege Escalation" "info"
    }

    # Windows Server 2019 RCE vulnerabilities

    # CVE-2021-26413: Windows HTTP.sys Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558994" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-26413: Windows HTTP.sys patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-26413: Windows HTTP.sys patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2019" "info"
        dsplMessage "           Affected Module: HTTP.sys - Remote Code Execution" "info"
    }

    # CVE-2021-36934: Windows DNS Server Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558993" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-36934: Windows DNS Server patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-36934: Windows DNS Server patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2019" "info"
        dsplMessage "           Affected Module: DNS Server - Remote Code Execution" "info"
    }

    # CVE-2021-40449: Windows SMBv3 Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB4558996" }
    if ($hotfix) {
        dsplMessage "       CVE-2021-40449: Windows SMBv3 patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2021-40449: Windows SMBv3 patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2019" "info"
        dsplMessage "           Affected Module: SMBv3 - Remote Code Execution" "info"
    }

    # Windows Server 2022 LPE vulnerabilities

    # CVE-2022-22013: Windows AppX Package Manager Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015564" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-22013: Windows AppX Package Manager patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-22013: Windows AppX Package Manager patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2022" "info"
        dsplMessage "           Affected Module: AppX Package Manager - Local privilege Escalation" "info"
    }

    # CVE-2022-24491: Windows Print Spooler Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015563" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-24491: Windows Print Spooler patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-24491: Windows Print Spooler patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2022" "info"
        dsplMessage "           Affected Module: Print Spooler - Local privilege Escalation" "info"
    }

    # CVE-2022-26938: Windows Kernel Elevation of Privilege Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015562" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-26938: Windows Kernel patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-26938: Windows Kernel patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2022" "info"
        dsplMessage "           Affected Module: Kernel - Local privilege Escalation" "info"
    }

    # Windows Server 2022 RCE vulnerabilities

    # CVE-2022-22014: Windows HTTP.sys Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015565" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-22014: Windows HTTP.sys patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-22014: Windows HTTP.sys patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2022" "info"
        dsplMessage "           Affected Module: HTTP.sys - Remote Code Execution" "info"
    }

    # CVE-2022-24492: Windows DNS Server Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015564" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-24492: Windows DNS Server patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-24492: Windows DNS Server patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2022" "info"
        dsplMessage "           Affected Module: DNS Server - Remote Code Execution" "info"
    }

    # CVE-2022-26937: Windows SMBv3 Remote Code Execution Vulnerability
    $hotfix = Get-HotFix | Where-Object { $_.HotFixID -eq "KB5015561" }
    if ($hotfix) {
        dsplMessage "       CVE-2022-26937: Windows SMBv3 patch is installed :)" "success"
    } else {
        dsplMessage "       CVE-2022-26937: Windows SMBv3 patch is NOT installed!" "error"
        dsplMessage "           Affects: Windows Server 2022" "info"
        dsplMessage "           Affected Module: SMBv3 - Remote Code Execution" "info"
    }
}

function Get-ClearTextPasswords {
    dsplMessage "Clear-text and Base64 Passwords Search" "info"
    dsplMessage "=====================================" "info"
    dsplMessage "       This may take some time." "warning"
    try {
        # Define an array of common folders to search
        $folders = @(
            "$env:SystemDrive\sysprep",
            "$env:WINDIR\Panther",
            "$env:WINDIR\Panther\Unattend",
            "$env:SystemDrive\inetpub\wwwroot\web.config",
            "$env:SystemDrive\Program Files\OpenVPN\config",
            "$env:SystemDrive\ProgramData\Microsoft\Credentials",
            "$env:APPDATA\FileZilla\recentservers.xml",
            "$env:APPDATA\FileZilla\sitemanager.xml",
            "$env:WINDIR\System32\inetsrv\config",
            "$env:WINDIR\System32\inetsrv\config\applicationHost.config",
            "$env:WINDIR\System32\inetsrv\config\administration.config",
            "$env:WINDIR\System32\inetsrv\config\redirection.config",
            "$env:WINDIR\System32\inetsrv\config\schema",
            "$env:SystemDrive\inetpub\wwwroot",
            "$env:SystemDrive\xampp",
            "$env:SystemDrive\Program Files\IIS Express\config",
            "$env:SystemDrive\Program Files (x86)\IIS Express\config",
            "$env:SystemDrive\ProgramData\MySQL\MySQL Server 5.5\data",
            "$env:SystemDrive\ProgramData\MySQL\MySQL Server 5.6\data",
            "$env:SystemDrive\ProgramData\MySQL\MySQL Server 5.7\data",
            "$env:SystemDrive\ProgramData\MySQL\MySQL Server 8.0\data",
            "$env:SystemDrive\ProgramData\Microsoft\Crypto\RSA\S-1-5-18",
            "$env:SystemDrive\ProgramData\Microsoft\Credentials",
            "$env:SystemDrive\ProgramData\Microsoft\Windows\SystemData\",
            "$env:USERPROFILE\.azure\",
            "$env:USERPROFILE\.aws",
            "$env:APPDATA\Roaming\gcloud\",
            "$env:SystemDrive\Users\Public",
            "$env:SystemDrive\Windows\SYSVOL\sysvol\",
            "$env:SystemDrive\Program Files (x86)\hMailServer"
            #"$env:USERPROFILE\Documents"
        )

        # Define an array of file extensions or names to search
        $fileExtensions = @(
            "*.config",
            "*.conf",
            "*.py", 
            ".pyc", 
            ".pyi",
            "*.js", 
            "*.html", 
            "*.c", 
            "*.cpp", 
            "*.pl", 
            "*.rb", 
            "*.java", 
            "*.php", 
            "*.bat", 
            "*.ps1",
            "*.sh",
            "*.xml",
            "*.txt",
            "*.text", 
            "*.md",
            "*.markdown", 
            "*.toml", 
            "*.rtf",
            "*.ini",
            "*.cfg",
            "*.ini",
            "*.id_rsa",
            "*.id_dsa", 
            "*.bash_history", 
            "*.rsa",
            "*.y*ml",
            "*.log",
            "*.bak"
        )

        # Function to search for clear-text passwords in a file
        function SearchPasswordsInFile {
            param(
                [string]$filePath
            )
        
            try {
                # Debug output: Show which file is being searched
                #Write-Host "Searching file: $filePath"
        
                $content = Get-Content -Path $filePath -ErrorAction Stop
        
                # Define an array of regex patterns to match passwords
                $passwordPatterns = @(
                    "(password|passwd|PASSWD|PASSWORD|PWD|pwd|pass|p4ss|p422)=(.+)",               # Common passwords
                    "(user|username|usr|login)=(.+)",                          # Usernames or logins
                    "(email|e-mail|mail)=(.+)",                                # Email Scan
                    "(api_key|api_secret)=(.+)",                               # API tokens or secrets  (token removed from pattern due to vast amount of false positives)
                    "(access_key|access_token)=(.+)",                          # Access keys or tokens
                    "(auth_key|auth_token)=(.+)",                              # Authentication keys or tokens
                    "(client_secret|client_id)=(.+)",                          # Client secrets or IDs
                    "(db_pass|db_pwd|db_password|dbuser|dbpass)=(.+)",         # Database passwords
                    "(ftp_pass|ftp_pwd|ftp_password)=(.+)",                    # FTP passwords
                    "(ssh_pass|ssh_pwd|ssh_password)=(.+)",                    # SSH passwords
                    "(smtp_pass|smtp_pwd|smtp_password)=(.+)",                 # SMTP passwords
                    "(rsa_private_key|rsa_public_key)=(.+)",                   # RSA keys
                    "(ssl_cert_key|ssl_cert_pwd)=(.+)",                        # SSL certificate keys or passwords
                    "(aes_key|aes_pwd)=(.+)",                                  # AES keys or passwords
                    "(bcrypt_hash)=(.+)",                                      # Bcrypt hashes
                    "(jwt_token)=(.+)",                                        # JWT tokens
                    "(api_secret_key)=(.+)",                                   # API secret keys
                    "(oauth_token)=(.+)",                                      # OAuth tokens
                    "(private_key)=(.+)",                                      # Private keys
                    "(bearer_token)=(.+)",                                     # Bearer tokens
                    "(client_certificate)=(.+)",                               # Client certificates
                    "(client_token)=(.+)",                                     # Client tokens
                    "(refresh_token)=(.+)",                                     # Refresh tokens
                    "(private)=(.+)"                                           # Sneaky people
                )
        
                foreach ($pattern in $passwordPatterns) {
                    if ($content -match $pattern) {
                        dsplMessage "File: $filePath" "info"
                        dsplMessage "------------------------" "info"
                        $match3s = $content | Select-String -Pattern $pattern -AllMatches
                        foreach ($match in $match3s.Matches) {
                            $passwordLine = $match.Value.Trim()
                            dsplMessage "Potential password or sensitive information found: $passwordLine" "error"
                        }
                        Write-Host ""
                    }
                }
            } catch {
                dsplMessage "Error reading file: $filePath. $_" "error"
            }
        }

        # Loop through folders and search files with specified extensions
        foreach ($folder in $folders) {
            if (Test-Path $folder -PathType Container) {
                dsplMessage "Searching in folder: $folder" "info"
                
                foreach ($extension in $fileExtensions) {
                    $files = Get-ChildItem -Path $folder -Filter $extension -File -Recurse -ErrorAction SilentlyContinue
                    foreach ($file in $files) {
                        SearchPasswordsInFile -filePath $file.FullName
                    }
                }
            } else {
                dsplMessage "Folder $folder does not exist." "info"
            }
        }

        # Additional searches based on specific filenames or patterns
        $additionalFiles = @(
            "sysprep.inf",
            "sysprep.xml",
            "Unattended.xml",
            "*pass*",
            "*cred*",
            "*vnc*"
        )

        foreach ($filePattern in $additionalFiles) {
            $files = Get-ChildItem -Path $env:WINDIR -Recurse -File -Filter $filePattern -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                SearchPasswordsInFile -filePath $file.FullName
            }
        }

    } catch {
        dsplMessage "Error occurred while searching for clear-text passwords: $_" "error"
    }
}

############################################################
##### Main that makes the stuff actually do the stuff. #####
############################################################
# Define functions for different tasks
function Main {
    if ($Version) {
        dsplVersiona
        exit 0
    }

    # Define the array of functions to call
    $functionsToCall = @(  
    ## System Stuff
        @{ Name = "SystemInformation"; ScriptBlock = { Write-Host ""; Get-SystemInformation; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "AvailableDrives"; ScriptBlock = { Write-Host ""; Get-AvailableDrives; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "AntivirusDetections"; ScriptBlock = { Write-Host ""; Get-AntivirusDetections; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "RecentCommands"; ScriptBlock = { Write-Host ""; Get-RecentCommands; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "InstalledKB"; ScriptBlock = { Write-Host ""; Get-InstalledKB; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "RunningServices"; ScriptBlock = { Write-Host ""; Get-RunningServices; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "InstalledSoftware"; ScriptBlock = { Write-Host ""; Get-InstalledSoftware; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "RecentFiles"; ScriptBlock = { Write-Host ""; Get-RecentFiles; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "StartupPrograms"; ScriptBlock = { Write-Host ""; Get-StartupPrograms; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "EventLogs"; ScriptBlock = { Write-Host ""; Get-EventLogs; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "SystemLogs"; ScriptBlock = { Write-Host ""; Get-SystemLogs; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "RegistrySettings"; ScriptBlock = { Write-Host ""; Get-RegistrySettings; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "SensitiveRegistry"; ScriptBlock = { Write-Host ""; Get-SensitiveRegistryComponents; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "EnvironmentVariables"; ScriptBlock = { Write-Host ""; Get-EnvironmentVariables; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "ProcessList"; ScriptBlock = { Write-Host ""; Get-ProcessList; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "SystemCertificates"; ScriptBlock = { Write-Host ""; Get-SystemCertificates; Write-Host "================================================================="; Write-Host "" } }

    ## User Stuff
        @{ Name = "PasswordPolicy"; ScriptBlock = { Write-Host ""; Get-PasswordPolicy; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "LocalUsers"; ScriptBlock = { Write-Host ""; Get-LocalUsers; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "LocalGroups"; ScriptBlock = { Write-Host ""; Get-LocalGroups; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "LAPSInstallation"; ScriptBlock = { Write-Host ""; Get-LAPSInstallation; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "LSAProtectionStatus"; ScriptBlock = { Write-Host ""; Get-LSAProtectionStatus -Verbose; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "CredentialGuardStatus"; ScriptBlock = { Write-Host ""; Get-CredentialGuardStatus -Verbose; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "UACStatus"; ScriptBlock = { Write-Host ""; Get-UACStatus; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "UserRights"; ScriptBlock = { Write-Host ""; Get-UserRights; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "UserSessions"; ScriptBlock = { Write-Host ""; Get-UserSessions; Write-Host "================================================================="; Write-Host "" } }

    ## Network Stuff
        @{ Name = "OpenPorts"; ScriptBlock = { Write-Host ""; Get-OpenPorts; Write-Host "================================================================="; Write-Host "" } }
    #   @{ Name = "Netstat"; ScriptBlock = { Write-Host ""; Get-Netstat; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "FirewallRules"; ScriptBlock = { Write-Host ""; Get-FirewallRules; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "RemoteDesktopSessions"; ScriptBlock = { Write-Host ""; Get-RemoteDesktopSessions; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "NetworkConfiguration"; ScriptBlock = { Write-Host ""; Get-NetworkConfiguration; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "NetworkShares"; ScriptBlock = { Write-Host ""; Get-NetworkShares; Write-Host "================================================================="; Write-Host "" } }

    ## Do we actually need it stuff?
    #   @{ Name = "Printers"; ScriptBlock = { Write-Host ""; Get-Printers; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "Check4RCE"; ScriptBlock = { Write-Host ""; Get-PossibleRCELPE; Write-Host "================================================================="; Write-Host "" } }
        @{ Name = "Check4Passwd"; ScriptBlock = { Write-Host ""; Get-ClearTextPasswords; Write-Host "================================================================="; Write-Host "" } }
    
    ## Active Directory and Important Folder Stuff
    # Doing this last because it can be a bit buggy
    @{ Name = "ActiveDirectoryInformation"; ScriptBlock = { Write-Host ""; Get-ActiveDirectoryInformation; Write-Host "================================================================="; Write-Host "" } }
    @{ Name = "CommonFolderPermissions"; ScriptBlock = { Write-Host ""; Get-CommonFolderPermissions; Write-Host "================================================================="; Write-Host "" } }
    @{ Name = "SharphoundEnum"; ScriptBlock = { Write-Host ""; Get-Sharphound; Write-Host "================================================================="; Write-Host "" } }

        
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
