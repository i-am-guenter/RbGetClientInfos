<#
.SYNOPSIS
    Reads IPs and/or hostname from input csv file exported by the splunk query.
    Performing a DNS lookup for each entry and add more details to the entries by querying Active Directory
    
.NOTES

.DESCRIPTION

.PARAMETER inputFile
Path to the file, exported from Splunk query. The file includes basic information and following headers/columns:
        final_hostname, 
        final_ip, 
        _time, 
        final_ip_type, 
        final_ip_subnet_network_type, 
        final_ip_zone,
        final_ip_zone_location,
        metisCreatedDate,
        shortDescription,
        primarySupportGroup,
        primaryUsedBy

.PARAMETER outputFile

.PARAMETER logFile

.EXAMPLE
Get-ClientInfo.ps1 -Inputfile filename.csv -Outputfile yyyy-mm-dd_hh-mm_export.csv -Logfile yyy-mm-dd_hh-mm_exportlog.log

#>

param(
    # csv input file from Splunk query

    [Parameter(Mandatory=$false)]
    [string]$Inputfile,
    [string]$OutputFile = ("./outputs/{0:yyyyMMdd_HHmm}_output.csv" -f (Get-Date)),
    [string]$Logfile = ("./logs/{0:yyyyMMdd_HHmm}_exportlogfile.log" -f (Get-Date)),
    [bool]$OnlyNaHosts = $false
)

# --- Helper Functions ---
# Log all events to the logfiles
function Write-Log ($message, [string]$level="INFO") {
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timeStamp] [$level] $message"
    
    $color = "Cyan"
    if ($level -eq "ERROR") { $color = "Red" }
    elseif ($level -eq "WARN") { $color = "Yellow" }
    elseif ($level -eq "DEBUG") { $color = "DarkMagenta" }
    
    Write-Host $logLine -ForegroundColor $color
    Add-Content -Path $Logfile -Value $logLine -ErrorAction SilentlyContinue
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

function GetOuNameByIpZoneLocation {
    param(
        [string]$inputString
    )

    $regexPattern = "(?<g1>\w{2})_(?<g2>\w{2,3})_(?<g3>.*)"
    
    if ($inputString -match $regexPattern) {
        return $Matches['g2']
    }
    return $null
}

function GetAdObjectFromGc {
    param(
        [string]$objectClass,
        [string]$objectName,
        [object]$dsSearcher
    )
    try 
    {
        $searcher.Filter = "(&(objectClass=$objectClass)(name=$objectName))"
        $dsResult = $searcher.FindOne()

        return $dsResult
    } catch
    {
        Write-Log "Error occurred while querying the $objectClass $objectName" "ERROR"
    }
}

function GetCountryNameByIsoCode {
    # PowerShell script to get country name from ISO code using REST API

    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z]{2}$')]  # Ensure exactly 2 letters
        [string]$IsoCode
    )

    try {
        # Normalize to uppercase
        $IsoCode = $IsoCode.ToUpper()

        # API endpoint for ISO code lookup
        $url = "https://restcountries.com/v3.1/alpha/$IsoCode"

        # Call the API
        $response = Invoke-RestMethod -Uri $url -Method GET -ErrorAction Stop

        if ($null -ne $response) {
            # Extract the common country name
            $countryName = $response.name.common
            Write-Log "ISO Code '$IsoCode' corresponds to: $countryName" "INFO"
            return $countryName
        }
        else {
            Write-Log "No country found for ISO code '$IsoCode'." "WARN"
            return $null
        }
    }
    catch [System.Net.WebException] {
        Write-Error "Network or API error: $($_.Exception.Message)"
    }
    catch {
        Write-Error "Unexpected error: $($_.Exception.Message)"
    }
}
# --- Initialization ---

$ErrorActionPreference = "Stop"

try {
    # 1. Validate Input File
    if ([string]::IsNullOrWhiteSpace($Inputfile)) {
        Write-Log "No input parameter specified. Starting dialog..."
        $Inputfile = Get-FileNameViaGui
        if (-not $Inputfile) {
            Write-Log "No file selected. Script will exit." "ERROR"
            exit
        }
    }

    Write-Log "Starting processing of: $Inputfile"

    # 2. Prepare AD Searcher (Global Catalog)
    $rootDSE = [adsi]"LDAP://RootDSE"
    $forestName = $rootDSE.rootDomainNamingContext
    $gcPath = "GC://$forestName"
    
    Write-Log "Connecting to Global Catalog: $gcPath"

    $searcher = New-Object System.DirectoryServices.DirectorySearcher([adsi]$gcPath)
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("distinguishedName", "dNSHostName", "Name")) 

    # 3. Read CSV
    # Reading without header to access column 1 and 2 by index (Col1, Col2)

    $csvData = Import-Csv -Path $Inputfile
    $rawData = $csvData | Sort-Object final_ip -Unique
    Write-Log "Processing $($rawData.Count) of $($csvData.Count) entries." 
    
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    foreach ($row in $rawData) {
        # Skip header if present
        if ($row.final_hostname -eq "final_hostname" -and $row.final_ip -eq "final_ip") { continue }
        
        # Optional: Skip rows with hostname other than "na" process entries with hostname 'na'
        if ($OnlyNaHosts -and $row.final_hostname -ne "na") {continue} 

        $inputHost = $row.final_hostname
        $inputIP = $row.final_ip
        
        # Logic: Determine ID
        $searchId = $null
        $searchType = "Unknown"

        if ($inputIP -ne 'na' -and $inputHost -eq 'na') {
            $searchId = $inputIP
            $searchType = "IP"
        } elseif ($inputHost -ne 'na' -and $inuptIP -eq 'na') {
            $searchId = $inputHost
            $searchType = "Hostname"
        } elseif ($inputHost -ne 'na' -and  $inputIP -ne 'na') {
            $searchId = $finalHost
            $searchType = "Skip"
            Write-Log "Hostname and IP known. No name resolution needed for host $inputHost ($inputIP)."
        } else {
            $searchType = "None"
            $searchId = "na"
            continue
        }


        if ($row.final_hostname -ne "na") { $pk = $row.final_hostname }
        if ($row.final_hostname -eq "na") { $pk = $row.final_ip }


        # Reset Output Variables

        $finalHostname = $null
        $finalIP = $null
        $finalLocationL = $null
        $finalCountryIso = $null   
        $finalCountryName = $null
        $finalLocAbbrev = $null
        $compDn = $null
        $finalOuDn = $null

 
        Write-Log "Processing ID: $($row.final_hostname) ($searchType)  - PK: $pk"

        # --- Step 1 & 2: DNS & Hostname Resolution ---
        
        $dnsResolved = $false
    
        try {
            if ($searchType -eq "IP") {
                # Reverse Lookup
                $dnsEntry = [System.Net.Dns]::GetHostEntry($SearchId)
                $finalHostname = ($dnsEntry.HostName).Split(".")[0]
                $finalIP = $searchId
                $dnsResolved = $true
                $nameResolutionResult = "Success_IP"
            } elseif ($searchType -eq "Hostname") {
                # Forward Lookup
                $dnsEntry = [System.Net.Dns]::GetHostEntry($SearchId)
                $finalHostname = ($dnsEntry.HostName).Split(".")[0]
                $finalIP = ($dnsEntry.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
                $dnsResolved = $true
                $nameResolutionResult  = "Success_Host"
            } elseif ($searchType -eq "Skip") {
                $finalHostname = $row.final_hostname
                $finalIP = $row.final_ip
                $dnsResolved = $true
                $nameResolutionResult  = "Skip"
            }
        } catch {
            Write-Log "DNS resolution error for  $SearchId : $($_.Exception.Message)" "WARN"
            $finalIP = if($searchType -eq "IP") { $searchId } else { "na" }
            $finalHostname = if ($searchType -eq "Hostname") { $searchId } else { "na" }
            $nameResolutionResult  = "Failure"
        }

        # --- Step 3 & 4: AD Search & Top-Level OU Info ---
        
        if ($dnsResolved -and $finalHostname) {
            try 
            {
                # Try to get AD object from AD (GC)
                $adObject = GetAdObjectFromGc -dsSearcher $searcher -objectClass "computer" -objectName $finalHostname
                
                if ($adObject) 
                {
                    # Write properties
                    $compDN = $adObject.Properties["distinguishedname"][0]
                    Write-Log "AD Object found: $compDN" "INFO"

                    # ---------------------------------------------------------
                    # Find Top-Level OU after domain part (DC=)
                    # ---------------------------------------------------------
                
                    $dnParts = $compDN -split ","
                    $targetOuDN = $null
                    # Write-Log "Before if switch: $compDN ($($dnParts.Count))" "DEBUG"
                    
                    # if ($null -eq $dnParts) {Write-Host "dnParts is empty"}
                    if (($dnParts -contains 'OU=Applications') -or ($dnParts -contains 'CN=Computers'))
                    {
                        # Write-Log "After if switch: $compDN ($($dnParts.Count))" "DEBUG"
                        Write-Log -message "Non location OU determined" -level "WARN"
                        $loc = GetOuNameByIpZoneLocation -inputString $row.final_ip_zone_location
                        if ($loc)
                        {
                            $searcher.Filter = "(&(objectClass=OrganizationalUnit)(Name=$loc))"
                            $ouObject = GetAdObjectFromGc -dsSearcher $searcher -objectClass "OrganizationalUnit" -objectName $loc
                            $targetOuDN = $ouObject.Properties["distinguishedName"][0]
                        }
                    } else 
                    {
                        for ($i = $dnParts.Count - 1; $i -ge 0; $i--) 
                        {
                            $part = $dnParts[$i].Trim()
                        
                            if ($part -match "^DC=") { continue }
                            if ($part -match "^OU=") 
                            {
                                # Reconstruct the DN for the OU with all parts from current index $i
                                $targetOuDN = ($dnParts[$i..($dnParts.Count - 1)]) -join ","
                            }
                            break
                        }
                    }
                } else {
                    Write-Log "No AD object for $finalHostname found in the forest. Searching Location from IP zone..." "WARN"
                    $location = GetOuNameByIpZoneLocation -inputString $row.final_ip_zone_location
                    if ($location)
                    {
                        $targetOuObject = GetAdObjectFromGc -dsSearcher $searcher -objectClass "OrganizationalUnit" -objectName $location
                        $targetOuDN = $targetOuObject.Properties["distinguishedName"][0]
                        Write-Log "Found OU object is $targetOuDN"
                    } else {
                        Write-Log "No location OU found for the object." "WARN"
                    }
                }


                if ($targetOuDN) {
                    Write-Log "Top-Level OU determined: $targetOuDN"
                    $ouEntry = [adsi]"LDAP://$targetOuDN"
                    
                    # Read Attributes from Organizational Unit
                    
                    # OU property 'l' for location
                    if ($ouEntry.Properties.Contains("l")) {
                        $finalLocationL = $ouEntry.Properties["l"][0]
                    }

                    # OU property 'c' for country information
                    if ($ouEntry.Properties.Contains("c")) {
                        $finalCountryIso = $ouEntry.Properties["c"][0]
                        $finalCountryName = (GetCountryNameByIsoCode -IsoCode $finalCountryIso)
                    }

                    # OU property 'name' for OU name, thus location abbreviation
                    if ($ouEntry.Properties.Contains("name")) {
                        $finalLocAbbrev = $ouEntry.Properties["name"][0]
                    }

                    # OU property 'distinguishedName' for whole object path
                    if ($ouEntry.Properties.Contains("distinguishedName")) {
                        $finalOuDn = $ouEntry.Properties["distinguishedName"][0]
                    }
                <#
                    # OU property 'description' to get more optional additional information
                    if ($ouEntry.Properties.Contains("description")) {
                        $descriptionFromOu = $ouEntry.Properties["description"][0]
                    }
                #>
                } else {
                    Write-Log "Top-Level container is not a Location OU or could not be determined. Setting values to null."
                }

            } catch {
                Write-Log "AD Error while searching for $finalHostname : $($_.Exception.Message)" "ERROR"
            }
        }

        # Build Output Object
        $obj = [PSCustomObject]@{
            pk                              = $pk
            final_hostname                  = $finalHostname
            final_ip                        = $finalIP
            _time                           = $row._time
            final_ip_type                   = $row.final_ip_type
            final_ip_subnet_network_type    = $row.final_ip_subnet_network_type
            final_ip_zone                   = $row.final_ip_zone
            final_ip_zone_location          = $row.final_ip_zone_location
            metisCreatedDate                = $row.metisCreatedDate
            shortDescription                = $row.shortDescription
            primarySupportGroup             = $row.primarySupportGroup
            primaryUsedBy                   = $row.primaryUsedBy
            ComputerDn                      = $compDn
            OrgUnitDn                       = $finalOuDn
            LocationFromAd                  = $finalLocationL
            LocationAbbreviation            = $finalLocAbbrev
            CountryIso                      = $finalCountryIso
            CountryName                     = $finalCountryName
            NameResolutionResult             = $nameResolutionResult
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