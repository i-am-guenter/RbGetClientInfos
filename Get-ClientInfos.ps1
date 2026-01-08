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

        if ($row.final_hostname -eq 'na')  {
            $searchId = $row.final_ip
            $searchType = "IP"
        } else {
            $searchType ="NONE"
            Write-Log "Name resolution skipped for host $($row.final_hostname)" "WARN"
            # continue
        }

        if ($row.final_hostname -ne "na") { $pk = $row.final_hostname }
        if ($row.final_hostname -eq "na") { $pk = $row.final_ip }


        # Reset Output Variables

        $finalHostname = $null
        $finalIP = $null
        $finalLocationL = $null
        $finalCountry = $null   
        $finalLocAbbrev = $null
        $compDn = $null
        $finalOuDn = $null
        $finalCountry = $null
        $descriptionFromOu = $null

 
        Write-Log "Processing ID: $searchId ($searchType)  - Host: $($row.final_hostname)"

        # --- Step 1 & 2: DNS & Hostname Resolution ---
        
        $dnsResolved = $false
        
        try {
            if ($searchType -eq "IP") {
                $dnsEntry = [System.Net.Dns]::GetHostEntry($searchId)
                $finalHostname = ($dnsEntry.HostName).Split(".")[0]
                $finalIP = $searchId
                $dnsResolved = $true
            } else {
                $dnsResolved = $true
                $finalIP = $row.final_ip
                $finalHostname = $row.final_hostname
            }
        } catch {
            Write-Log "DNS Error for $searchId : $($_.Exception.Message)" "WARN"
            if($searchType -eq "IP") { $finalIP = $searchId }
        }

        # --- Step 3 & 4: AD Search & Top-Level OU Info ---

        if ($dnsResolved -and $finalHostname) {
            
            $searcher.Filter = "(&(objectClass=computer)(Name=$finalHostname))"
            
            try {
                $searchResult = $searcher.FindOne()

                if ($searchResult) {
                    $compDN = $searchResult.Properties["distinguishedName"][0]
                    Write-Log "AD Object found: $compDN"

                    # ---------------------------------------------------------
                    # Find Top-Level OU after domain part (DC=)
                    # ---------------------------------------------------------
                    
                    $dnParts = $compDN -split ","
                    $targetOuDN = $null


                    if ($dnParts -contains 'OU=Applications')
                    {
                        Write-Log -message "Application OU determined" -level "WARN"
                            <# Action to perform. You can use $ to reference the current instance of this class #>
                        $loc = GetOuNameByIpZoneLocation -inputString $row.final_ip_zone_location
                        if ($loc)
                        {
                            $searcher.Filter = "(&(objectClass=OrganizationalUnit)(Name=$loc))"
                            $targetOuDn2 = $searcher.FindOne()
                            $targetOuDN = $targetOuDn2.Properties["distinguishedName"][0]
                            $fromApplicationOu = $true
                        }
                    } else {
                        for ($i = $dnParts.Count - 1; $i -ge 0; $i--) {
                            $part = $dnParts[$i].Trim()
                        
                            if ($part -match "^DC=") { continue }
                                if ($part -match "^OU=") {

                                # Reconstruct the DN for the OU with all parts from current index $i
                                $targetOuDN = ($dnParts[$i..($dnParts.Count - 1)]) -join ","
                            }
                            $fromApplicationOu = $false
                            break
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
                            $finalCountry = $ouEntry.Properties["c"][0]
                        }

                        # OU property 'name' for OU name, thus location abbreviation
                        if ($ouEntry.Properties.Contains("name")) {
                            $finalLocAbbrev = $ouEntry.Properties["name"][0]
                        }

                        # OU property 'distinguishedName' for whole object path
                        if ($ouEntry.Properties.Contains("distinguishedName")) {
                            $finalOuDn = $ouEntry.Properties["distinguishedName"][0]
                       }

                       # OU property 'description' to get more optional additional information
                        if ($ouEntry.Properties.Contains("description")) {
                            $descriptionFromOu = $ouEntry.Properties["description"][0]
                        }
                    } else {
                        Write-Log "Top-Level container is not an OU or could not be determined. Setting values to null."
                    }
                    # ---------------------------------------------------------

                } else {
                    Write-Log "No Computer object found in GC for: $finalHostname" "WARN"
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
            LocationFromAd                  = $finalLocation
            CountryFromAd                   = $finalCountry
            LocationAbbreviation            = $finalLocAbbrev
            OuObjectDescription             = $descriptionFromOu
            FromApplicationOu               = $fromApplicationOu
        }
        Write-Debug $obj
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