<#
.SYNOPSIS

    
.NOTES
    AUTHOR:     Günter Bayerl (BD/WPA-WCS1)
    Date:       12.01.2026
    

.DESCRIPTION
    The script is needed to prepare the Splunk query output to be used for communication with customers.
    As input the csv from Splunk is used. It reads IPs and/or hostname from the file and enriches the output
    with location and country information by performing a DNS lookup for each entry and add more details to 
    the entries by querying Active Directory
    The output will be written into an csv file. All steps are logged to an logfile.

    ### Change log:
    16.01.2026 - Bayerl Guenter (BSH-WP-WCS1)
        - Added filter for office networks to skip entries with an office subnet (WLAN, OFFICE, RASVPN.... )
        - Added support for other forests. Currently integrated are BCD and BSH

.PARAMETER InputFile


.PARAMETER OutputFile


.PARAMETER LogFile


.EXAMPLE

    Get-ClientInfo.ps1 -Inputfile filename.csv -Outputfile yyyy-mm-dd_hh-mm_export.csv -Logfile yyy-mm-dd_hh-mm_exportlog.log

#>

param(
    
    # Path to csv input file from Splunk query
    [Parameter(Mandatory=$true)][string]$Inputfile,

    # Path to csv output file with enriched data from AD.
    [Parameter(Mandatory=$false)][string]$OutputFile = ("./outputs/{0:yyyyMMdd_HHmm}_output.csv" -f (Get-Date)),

    # Path to lo the logfile to logging the script tasks
    [Parameter(Mandatory=$false)][string]$Logfile = ("./logs/{0:yyyyMMdd_HHmm}_exportlogfile.log" -f (Get-Date)),

    # Switch to perform enrichment only on lines, with 'na' value in ip or hostname column 
    [Parameter(Mandatory=$false)][bool]$OnlyNaHosts = $false,

    # Switch to define a different forest than the one, the client is member of
    [Parameter(Mandatory=$false)][ValidateSet("BCD","BSH")][string]$ActiveDirectoryForest
)



# -------------------- HELPER FUNCTIONS --------------------
function Write-Log {
    <# 
        # --- Function 'Write-Log' ---

        This function is used to write logging information to the logfile from the output parameter and to the screen.

        .PARAMETER $message
            This parameter is mandatory and holds the log message with details.
    
        .PARAMETER $level
            This parameter defines the log level. Log levels could be:
                - INFO (Default value)
                - WARN
                - ERROR
                - FATAL
                - DEBUG
    #>

    param(
        [Parameter(mandatory=$true)][string]$message, 
        [Parameter(mandatory=$true)][string]$level="INFO"
        ) 
    
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timeStamp] [$level] $message"
    
    $backgroundColor = "Black"

    if ($level -eq "INFO") { $foregroundColor = "Cyan" }
    elseif ($level -eq "WARN") { $foregroundColor = "DarkYellow" }
    elseif ($level -eq "ERROR") { $foregroundColor = "DarkRed" }
    elseif ($level -eq "FATAL") { $foregroundColor = "DarkMagenta"}
    elseif ($level -eq "DEBUG") { $foregroundColor = "DarkGreen" }
    else {$foregroundColor = "DarkGray"}

    Write-Host $logLine -ForegroundColor $foregroundColor -BackgroundColor $backgroundColor
    Add-Content -Path $Logfile -Value $logLine -ErrorAction SilentlyContinue
}
 
function Get-FileNameViaGui {
    <# 
        # --- Function 'Get-FileNameViaGui' ---
        .DESCRIPTION
        This function is used to pick the input file in case, no filename is provided on running the script via commandline parameter.
        The function returns the file path or $null in case no file is selected or CANCEL has been clicked.

        .NOTES
        Currently the function is not used, as the $inputFile parameter at the main script is mandatory.
    #>

    Add-Type -AssemblyName System.Windows.Forms
    $fileBrowser = New-Object System.Windows.Forms.OpenFileDialog
    $fileBrowser.Filter = 'CSV Files (*.csv)|*.csv|All Files (*.*)|*.*'
    $fileBrowser.Title = 'Please select the splunk query export CSV file'
    
    if ($fileBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $fileBrowser.FileName
    } else {
        return $null
    }
}

function GetOuNameByIpZoneLocation {
    <# 
        # --- Function 'GetOuNameByIpZoneLocation' ---
        .DESCRIPTION
        This function is used analyze the value in column 'final_ip_zone_location' to get the information about the
        location OU, if AD object is stored not in a location OU path.
        the mid part of the value will be extracted.
        The function returns the file path or $null in case no file is selected or CANCEL has been clicked.

        .EXAMPLE
        function input parameter value: BE_Ti_Tienen
        Information about location OU name: Ti
    #>
    param(
        # Value of column final_ip_zone_location from splunk output csv file.
        [Parameter(Mandatory=$true)][string]$inputString
    )

    # filter regex string to only use lines with the default format (2 letters _ 2 or 3 letters _ *)
    # values between _ are stored in regex groups country, locationShort, locationLong
    $regexPattern = "(?<country>\w{2})_(?<locationShort>\w{2,3})_(?<locationLong>.*)"
    

    if ($inputString -match $regexPattern) {
        return $Matches['locationShort']
    }
    return $null
}

function GetAdObjectFromGc {
    <# 
        # --- Function 'GetAdObjectFromGc' ---

        This function is used to connect to the Active Directory and return the Directory Searcher object if an AD object is found.

        .PARAMETER $objectClass
            The parameter is needed to define the object type/class to be searched. Possible classes are:
                - computer
                - organizationalunit
                - group
    
        .PARAMETER $objectName
            This parameter is needed to define the name of the object, which should be found. It is the name property of the AD object.

        .PARAMETER $dsSearcher
            This is parameter hands over the pre initialized searcher object from the DirectorySearcher dotnet class, which is needed to
            perform the search.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$objectClass,
        [Parameter(Mandatory=$true)][string]$objectName,
        [Parameter(Mandatory=$true)][object]$dsSearcher
    )
    try 
    {
        # Defines the filter. For this script only the combination of class and object name is needed.
        $searcher.Filter = "(&(objectClass=$objectClass)(name=$objectName))"

        # Perform the search and return only the first or only result, if any object is found.
        $dsResult = $searcher.FindOne()
        
        # Return the result the DirectorySearcher in case any object(s) found.  
        return $dsResult
    } catch
    {
        # In case no object is found, A log entry will be created and logged to file and terminal. 
        Write-Log "Error occurred while querying the $objectClass $objectName" "ERROR"
    }
}

function GetCountryNameByIsoCode {
    <# 
        # --- Function 'GetCountrynameByIsoCode' ---

        This function connects to an API to translate location abbreviation, like DE to the name Germany.

        .PARAMETER $isoCode
            This parameter is mandatory and holds the log message with details.
    
    #>
    # PowerShell script to get country name from ISO code using REST API

    param (
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z]{2}$')][string]$isoCode
    )

    try {
        # Normalize to uppercase
        $isoCode = $isoCode.ToUpper()

        # Api endpoint url to gather detailed country information.
        $url = "https://restcountries.com/v3.1/alpha/$isoCode"

        # Call the API
        $response = Invoke-RestMethod -Uri $url -Method GET -ErrorAction Stop

        if ($null -ne $response) {
            # Extract the common country name
            $countryName = $response.name.common
            
            # Write log information to file and terminal.
            Write-Log "ISO Code '$IsoCode' corresponds to: $countryName" "INFO"
            
            # Returns the country name
            return $countryName
        }
        else {
            # If the country cannot be found, an exception will be written to the logfile and return $null.
            Write-Log "No country found for ISO code '$IsoCode'." "WARN"
            return $null
        }
    }
    catch [System.Net.WebException] {
        # Catch an exception in case the Api could not be reached and log it to the logfile and terminal.
        Write-Error "Network or API error: $($_.Exception.Message)"
    }
    catch {
        # Write an error to the logfile and terminal in case of any other unexpected exception.
        Write-Error "Unexpected error: $($_.Exception.Message)"
    }
}

# -------------------- END OF HELPER FUNCTIONS SECTION --------------------

# -------------------- MAIN FUNCTION --------------------
# Initializing
$ErrorActionPreference = "Stop"




try {
    # Validation of input csv file
    if ([string]::IsNullOrWhiteSpace($Inputfile)) {
        Write-Log "No input parameter specified. Starting dialog..." "INFO"
        $Inputfile = Get-FileNameViaGui
        if (-not $Inputfile) {
            Write-Log "No file selected. Script will exit." "ERROR"
            exit
        }
    }

    Write-Log "Start processing file: $Inputfile" "INFO"
  
    switch ($ActiveDirectoryForest) {
        {$_ -eq "BCD"} {$gcPath = "GC://DC=bosch,DC=com"}
        {$_ -eq "BSH"} {$gcPath = "GC://DC=corp,DC=bshg,DC=com"}
        Default {
            # Directory Searcher search root 
            $rootDSE = [adsi]"LDAP://RootDSE"

            # Name of current forest
            $forestName = $rootDSE.rootDomainNamingContext

            # Global catalog path from current environment/forest
            $gcPath = "GC://$forestName"
        }
    }

    Write-Log "Connected to Global Catalog: $gcPath" "INFO"

    # Initializing Subnet filter strings
    $subnetNetworkTypeFilter = @("WLAN", "Office", "Office_WLAN", "RASVPN")

    # Initializing Directory Searcher object
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([adsi]$gcPath)
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("distinguishedName", "dNSHostName", "Name")) 

    # Read input csv file, remove duplicates and ignore column headers.
    $csvData = Import-Csv -Path $Inputfile
    $rawData = $csvData | Sort-Object final_ip -Unique
    Write-Log "Processing $($rawData.Count) of $($csvData.Count) entries." "INFO"
    
    # Initialize object $result to hold the results to be export to the output csv file.
    $results = New-Object System.Collections.Generic.List[PSCustomObject]

    # Start processing data (csv lines) from input csv file.
    foreach ($row in $rawData) {

        # Skip header if present
        if ($row.final_hostname -eq "final_hostname" -and $row.final_ip -eq "final_ip") {
            Write-Log "Skip the header of the input csv file." "INFO"
            continue 
        }
        
        # Optional: Skip rows with hostname other than "na" process entries with hostname 'na'
        if ($OnlyNaHosts -and $row.final_hostname -ne "na") {
            Write-Log "Line has no 'na' value and will be skipped." "INFO"
            continue
        } 

    <#
        # Skip if subnet network type is for office devices.
        if ($subnetNetworkTypeFilter -contains $row.final_ip_subnet_network_type) {
            Write-Log "The subnet type $($row.final_ip_subnet_network_type) is on office zone and will be skipped." "INFO"
            continue
        }
    #>
        $inputHost = $row.final_hostname
        $inputIP = $row.final_ip
        $subnetType = $row.final_ip_subnet_network_type
   
        # Logic to define kind of dns resolution direction (forward or reverse lookup) or if to skip
        $searchId = $null
        $searchType = "Unknown"

        if ($inputIP -ne 'na' -and $inputHost -eq 'na' -and ($subnetNetworkTypeFilter -notcontains $subnetType)) {
            # Prepare for reverse dns lookup if only ip is available
            $searchId = $inputIP
            $searchType = "IP"
        } elseif ($inputHost -ne 'na' -and $inuptIP -eq 'na' -and ($subnetNetworkTypeFilter -notcontains $subnetType)) {
            # Prepare for forward dns lookup if only hostname is available
            $searchId = $inputHost
            $searchType = "HOST"
        } elseif ($inputHost -ne 'na' -and  $inputIP -ne 'na' -and ($subnetNetworkTypeFilter -notcontains $subnetType)) {
            # Prepare skipping lookup if both (ip and hostname) are present in input file
            $searchId = $finalHost
            $searchType = "SKIP"
            Write-Log "Hostname and IP known. No name resolution needed for host $inputHost ($inputIP)." "INFO"
        } elseif ($subnetNetworkTypeFilter -contains $row.final_ip_subnet_network_type){
            $searchType = "OFFICE"
            $searchId = $null
            Write-Log "The subnet type $($row.final_ip_subnet_network_type) is on office zone and will be skipped." "INFO"
        } else {
            # End script if neither ip nor hostname are present.
            $searchType = "NONE"
            $searchId = $null
            continue
        }

        # Set primary key (pk) depending on which value is provided in input file (ip and/or hostname)
        if ($row.final_hostname -ne "na") { $pk = $row.final_hostname }
        if ($row.final_hostname -eq "na") { $pk = $row.final_ip }


        # Reset output variables to $null
        $finalHostname = $null
        $finalIP = $null
        $finalLocationL = $null
        $finalCountryIso = $null   
        $finalCountryName = $null
        $finalLocAbbrev = $null
        $compDn = $null
        $finalOuDn = $null
 
        Write-Log "Processing ID: $($row.final_hostname) ($searchType)  - PK: $pk" "INFO"

        # Reset dns resolution status
        $dnsResolved = $false
    
        # Perform DNS resolution 
        try {
            if ($searchType -eq "IP") {
                # Perform reverse dns lookup
                $dnsEntry = [System.Net.Dns]::GetHostEntry($SearchId)
                $finalHostname = ($dnsEntry.HostName).Split(".")[0]
                $finalIP = $searchId
                $dnsResolved = $true
                $nameResolutionResult = "Success_IP"
            } elseif ($searchType -eq "HOST") {
                # Perform forward dns lookup
                $dnsEntry = [System.Net.Dns]::GetHostEntry($SearchId)
                $finalHostname = ($dnsEntry.HostName).Split(".")[0]
                $finalIP = ($dnsEntry.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
                $dnsResolved = $true
                $nameResolutionResult  = "Success_Host"
            } elseif ($searchType -eq "SKIP") {
                # Skip dns lookup as both (ip and hostname) are present in input file.
                $finalHostname = $row.final_hostname
                $finalIP = $row.final_ip
                $dnsResolved = $true
                $nameResolutionResult  = "Skip"
            } elseif ($searchType -eq 'OFFICE' -or $searchType -eq 'NONE') {
                $finalHostname = $row.final_hostname
                $finalIP = $row.final_ip
                $dnsResolved = $false
                $nameResolutionResult = "Skip_Office"
            }
        } catch {
            # Write error to logfile and terminal in case name resolution raises an error and fails and 
            # define default values to continue the script.
            Write-Log "DNS resolution error for  $SearchId : $($_.Exception.Message)" "WARN"
            $finalIP = if($searchType -eq "IP") { $searchId } else { "na" }
            $finalHostname = if ($searchType -eq "Hostname") { $searchId } else { "na" }
            $nameResolutionResult  = "Failure"
        }

        # Collect additional information from Active Directory or the input csv file for all entries, which have a valid ip or hostname present.
        
        if ($dnsResolved -and $finalHostname) {
            try 
            {
                # Try to get AD object from AD (GC) via Helper function
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
                    Write-Log "No AD object for $finalHostname found in the forest $forestName. Searching Location from IP zone..." "WARN"
                    $location = GetOuNameByIpZoneLocation -inputString $row.final_ip_zone_location
                    if ($location)
                    {
                        $targetOuObject = GetAdObjectFromGc -dsSearcher $searcher -objectClass "OrganizationalUnit" -objectName $location
                        $targetOuDN = $targetOuObject.Properties["distinguishedName"][0]
                        Write-Log "Found OU object is $targetOuDN" "INFO"
                    } else {
                        Write-Log "No location OU found for the object." "WARN"
                    }
                }


                if ($targetOuDN) {
                    Write-Log "Top-Level OU determined: $targetOuDN" "INFO"
                    $ouEntry = [adsi]"LDAP://$targetOuDN"
                    
                    # Read Attributes from location OU

                    # OU property 'l' for location name
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

                } else {
                    Write-Log "Top-Level container is not a Location OU or could not be determined. Setting values to null." "INFO"
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
    Write-Log "Exporting results to $outputFile" "INFO"
    $results | Export-Csv -Path $outputFile -NoTypeInformation -Delimiter ";" -Encoding UTF8

    Write-Log "Script finished successfully." "INFO"

} catch {
    Write-Log "Critical Error in script: $($_.Exception.Message)" "ERROR"
    exit 1
}