<#
.SYNOPSIS
    Reads IPs/Hostnames, performs DNS lookups, searches for computers in the AD Global Catalog,
    and retrieves location information based on the TOP-LEVEL OU (directly under DC).
    
    COMPATIBLE WITH POWERSHELL 5.1
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$csvFile,

    [Parameter(Mandatory=$true)]
    [string]$outputFile,

    [Parameter(Mandatory=$true)]
    [string]$logFile
)

# --- Helper Functions ---

function Write-Log {
    param([string]$message, [string]$level="INFO")
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timeStamp] [$level] $message"
    
    $color = "Cyan"
    if ($level -eq "ERROR") { $color = "Red" }
    elseif ($level -eq "WARN") { $color = "Yellow" }
    
    Write-Host $logLine -ForegroundColor $color
    Add-Content -Path $logFile -Value $logLine -ErrorAction SilentlyContinue
}

function Get-FileNameViaGui {
    Add-Type -AssemblyName System.Windows.Forms
    $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog
    $fileBrowser.Filter = 'CSV Files (*.csv)|*.csv|All Files (*.*)|*.*'
    $fileBrowser.Title = 'Please select a CSV file'
    
    if ($fileBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $fileBrowser.FileName
    } else {
        return $null
    }
}

# --- Initialization ---

$ErrorActionPreference = "Stop"

try {
    # 1. Validate Input File
    if ([string]::IsNullOrWhiteSpace($csvFile)) {
        Write-Log "No input parameter specified. Starting dialog..."
        $csvFile = Get-FileNameViaGui
        if (-not $csvFile) {
            Write-Log "No file selected. Script will exit." "ERROR"
            exit
        }
    }

    Write-Log "Starting processing of: $csvFile"

    # 2. Prepare AD Searcher (Global Catalog)
    $rootDSE = [adsi]"LDAP://RootDSE"
    $forestName = $rootDSE.rootDomainNamingContext
    $gcPath = "GC://$forestName"
    
    Write-Log "Connecting to Global Catalog: $gcPath"

    $searcher = New-Object System.DirectoryServices.DirectorySearcher([adsi]$gcPath)
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("distinguishedName", "dNSHostName")) 

    # 3. Read CSV
    # Reading without header to access column 1 and 2 by index (Col1, Col2)
    $rawData = Import-Csv -Path $csvFile -Header "Col1","Col2" -Delimiter ";" 

    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    foreach ($row in $rawData) {
        # Skip header if present
        if ($row.Col1 -eq "IP" -and $row.Col2 -eq "Hostname") { continue }

        $inputIP = $row.Col1
        $inputHost = $row.Col2
        
        # Logic: Determine ID
        $searchId = $null
        $searchType = "Unknown"

        if (-not [string]::IsNullOrWhiteSpace($inputIP)) {
            $searchId = $inputIP
            $searchType = "IP"
        } elseif (-not [string]::IsNullOrWhiteSpace($inputHost)) {
            $searchId = $inputHost
            $searchType = "Hostname"
        } else {
            Write-Log "Skipped line: Neither IP nor Hostname present." "WARN"
            continue
        }

        # Reset Output Variables
        $finalHostname = $null
        $finalIP = $null
        $finalLocation = $null    
        $finalCountry = $null     
        $finalLocAbbrev = $null   

        Write-Log "Processing ID: $searchId ($searchType)"

        # --- Step 1 & 2: DNS & Hostname Resolution ---
        
        $dnsResolved = $false
        
        try {
            if ($searchType -eq "IP") {
                $dnsEntry = [System.Net.Dns]::GetHostEntry($searchId)
                $finalHostname = $dnsEntry.HostName
                $finalIP = $searchId
                $dnsResolved = $true
            } else {
                $dnsEntry = [System.Net.Dns]::GetHostEntry($searchId)
                $finalHostname = $dnsEntry.HostName 
                # Get first IPv4
                $ipList = $dnsEntry.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                if ($ipList) { $finalIP = $ipList.IPAddressToString }
                $dnsResolved = $true
            }
        } catch {
            Write-Log "DNS Error for $searchId: $($_.Exception.Message)" "WARN"
            if($searchType -eq "IP") { $finalIP = $searchId }
        }

        # --- Step 3 & 4: AD Search & Top-Level OU Info ---

        if ($dnsResolved -and $finalHostname) {
            
            $searcher.Filter = "(&(objectClass=computer)(dNSHostName=$finalHostname))"
            
            try {
                $searchResult = $searcher.FindOne()

                if ($searchResult) {
                    $compDN = $searchResult.Properties["distinguishedName"][0]
                    Write-Log "AD Object found: $compDN"

                    # ---------------------------------------------------------
                    # LOGIC: Find Top-Level OU (directly under DC=...)
                    # ---------------------------------------------------------
                    
                    # Split DN at comma
                    $dnParts = $compDN -split ","
                    $targetOuDN = $null
                    
                    # Iterate from right (Root) to left (Leaf)
                    # Find the first part that DOES NOT start with "DC="
                    for ($i = $dnParts.Count - 1; $i -ge 0; $i--) {
                        $part = $dnParts[$i].Trim()
                        
                        # If we are still at DC=, continue
                        if ($part -match "^DC=") { continue }

                        # Found the first element after DCs.
                        # Check if it is an OU.
                        if ($part -match "^OU=") {
                            # Reconstruct the DN for this Top-Level OU
                            # It consists of all parts from current index $i to the end
                            $targetOuDN = ($dnParts[$i..($dnParts.Count - 1)]) -join ","
                        }
                        
                        # Stop as soon as we checked the first non-DC element.
                        # If it was CN= (Container), targetOuDN remains null -> correct per requirement.
                        break
                    }

                    if ($targetOuDN) {
                        Write-Log "Top-Level OU determined: $targetOuDN"
                        $ouEntry = [adsi]"LDAP://$targetOuDN"
                        
                        # Read Attributes (Schema Check not strictly needed as we checked regex "^OU=")
                        if ($ouEntry.Properties.Contains("l")) {
                            $finalLocation = $ouEntry.Properties["l"][0]
                        }
                        if ($ouEntry.Properties.Contains("co")) {
                            $finalCountry = $ouEntry.Properties["co"][0]
                        }
                        if ($ouEntry.Properties.Contains("name")) {
                            $finalLocAbbrev = $ouEntry.Properties["name"][0]
                        }
                    } else {
                        Write-Log "Top-Level container is not an OU or could not be determined. Setting values to null."
                    }
                    # ---------------------------------------------------------

                } else {
                    Write-Log "No Computer object found in GC for: $finalHostname" "WARN"
                }
            } catch {
                Write-Log "AD Error while searching for $finalHostname: $($_.Exception.Message)" "ERROR"
            }
        }

        # Build Output Object
        $obj = [PSCustomObject]@{
            Hostname             = $finalHostname
            IPAddress            = $finalIP
            Location             = $finalLocation
            Country              = $finalCountry
            LocationAbbreviation = $finalLocAbbrev
        }

        $results.Add($obj)
    }

    # Export
    Write-Log "Exporting results to $outputFile"
    $results | Export-Csv -Path $outputFile -NoTypeInformation -Delimiter ";" -Encoding UTF8

    Write-Log "Script finished successfully."

} catch {
    Write-Log "Critical Error in script: $($_.Exception.Message)" "ERROR"
    exit 1
}