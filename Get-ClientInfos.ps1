<#
.SYNOPSIS
    This script imports the csv file from the splunk output for legacy protocols and adds additional

.DESCRIPTION
    1. Import CSV (Parameter oder GUI).
    2. Priorisierung: IP > Hostname für die ID.
    3. DNS Lookup.
    4. AD Suche via DirectorySearcher (High Performance).
    5. Auslesen der Parent-OU Attribute (City, Country, Name).
    6. Logging und CSV Export.

.PARAMETER CsvFile
    Optional. Pfad zur Import-Datei. Wenn leer -> FileDialog.
    Erwartet Header-less CSV oder Header "IP","Hostname". 
    Das Script nimmt an: Spalte 1 = IP, Spalte 2 = Hostname.

.PARAMETER OutputFile
    Mandatory. Pfad für die Ergebnis-CSV.

.PARAMETER LogFile
    Mandatory. Pfad für das Logfile.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$CsvFile,

    [Parameter(Mandatory=$true)]
    [string]$OutputFile,

    [Parameter(Mandatory=$true)]
    [string]$LogFile
)

# --- Hilfsfunktionen ---

function Write-Log {
    param([string]$Message, [string]$Level="INFO")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogLine = "[$TimeStamp] [$Level] $Message"
    $color = "Cyan"
    if ($Level -eq "ERROR") {$color = "Red"}
    elseif ($Level -eq "WARN") {$color = "Yellow"}
    Write-Host $LogLine -ForegroundColor $color
    Add-Content -Path $LogFile -Value $LogLine -ErrorAction SilentlyContinue
}

function Get-FileName {
    Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
        Filter = 'CSV Files (*.csv)|*.csv|All Files (*.*)|*.*'
        Title = 'Bitte CSV-Datei auswählen'
    }
    if ($FileBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $FileBrowser.FileName
    } else {
        return $null
    }
}

# --- Initialisierung ---

$ErrorActionPreference = "Stop"

try {
    # 1. Input Datei validieren
    if ([string]::IsNullOrWhiteSpace($CsvFile)) {
        Write-Log "Kein Input-Parameter angegeben. Starte Dialog..."
        $CsvFile = Get-FileName
        if (-not $CsvFile) {
            Write-Log "Keine Datei ausgewählt. Script wird beendet." "ERROR"
            exit
        }
    }

    Write-Log "Starte Verarbeitung von: $CsvFile"

    # 2. AD Sucher vorbereiten (Global Catalog für Speed)
    # Wir suchen den Forest Root, um den GC anzusprechen
    $RootDSE = [adsi]"LDAP://RootDSE"
    $ForestName = $RootDSE.rootDomainNamingContext
    $GCPath = "GC://$ForestName"
    
    Write-Log "Verbinde mit Global Catalog: $GCPath"

    # DirectorySearcher Instanziieren (Schneller als Get-ADComputer)
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([adsi]$GCPath)
    $Searcher.PageSize = 1000 # Paging für große Umgebungen
    # Wir laden nur das Nötigste, um Traffic zu sparen
    $Searcher.PropertiesToLoad.AddRange(@("distinguishedName", "dNSHostName")) 

    # 3. CSV Einlesen
    # Wir lesen ohne Header, um Spalte 1 und 2 per Index anzusprechen, 
    # falls die CSV keine oder falsche Header hat.
    $RawData = Import-Csv -Path $CsvFile -Delimiter ","
    $Results = New-Object System.Collections.Generic.List[PSCustomObject]

    foreach ($Row in $RawData) {
        # Skip Header Line if it looks like a header (optional, simple check)
        if ($Row.final_hostname -eq "final_hostname" -and $Row.final_ip -eq "final_ip") { continue }

        $InputIP = $Row.final_ip
        $InputHost = $Row.final_hostname
        # Logik: ID Bestimmung
        $SearchId = $null
        $SearchType = "Unknown"

        if (-not [string]::IsNullOrWhiteSpace($InputIP)) {
            $SearchId = $InputIP
            $SearchType = "IP"
        } elseif (-not [string]::IsNullOrWhiteSpace($InputHost)) {
            $SearchId = $InputHost
            $SearchType = "Hostname"
        } else {
            Write-Log "Skip line. No IP or hostname found." "WARN"
            continue
        }

        # Initialisieren der Output-Variablen
        $FinalHostname = $null
        $FinalIP = $null
        $FinalLocation = $null    # City
        $FinalCountry = $null     # Country
        $FinalLocAbbrev = $null   # Name (OU)

        Write-Log "Verarbeite ID: $SearchId ($SearchType)"

        # --- Schritt 1 & 2: DNS & Hostname Ermittlung ---
        
        $DnsResolved = $false
        
        try {
            if ($SearchType -eq "IP") {
                # Reverse Lookup
                $DnsEntry = [System.Net.Dns]::GetHostEntry($SearchId)
                $finalHostname = $DnsEntry.HostName
                $hostname = $finalHostname.Split(".")[0]
                $FinalIP = $SearchId
                $DnsResolved = $true
            } else {
                # Forward Lookup (falls nur Hostname da war, brauchen wir IP für Output)
                $DnsEntry = [System.Net.Dns]::GetHostEntry($SearchId)
                $finalHostname = $DnsEntry.HostName # fqdn
                $hostname = $finalHostname.Split(".")[0]
                # Nehmen wir die erste IPv4 Adresse
                $FinalIP = ($DnsEntry.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
                $dnsResolved = $true
            }
        } catch {
            Write-Log "DNS Fehler für $SearchId : $($_.Exception.Message)" "WARN"
            $FinalIP = if($SearchType -eq "IP") { $SearchId } else { $null }
            # Wenn IP nicht auflösbar, wird laut Anforderung Objekt mit nulls erstellt (passiert am Ende)
        }

        # --- Schritt 3 & 4: AD Suche & Parent Info ---

        if ($dnsResolved -and $finalHostname) {
            # Extrahiere Hostname ohne Domain-Part für die Suche, falls nötig, 
            # aber dNSHostName Attribut ist meist FQDN. Wir suchen sicherheitshalber nach dNSHostName.
            $hostname
            $Searcher.Filter = "(&(objectClass=computer)(Name=$hostname))"
            
            try {
                $SearchResult = $Searcher.FindOne()

                if ($SearchResult) {
                    # Computer gefunden
                    $CompDN = $SearchResult.Properties["distinguishedName"][0]
                    Write-Log "AD Objekt gefunden: $CompDN"

                    # Parent Objekt holen
                    # Wir nutzen [adsi] mit LDAP (nicht GC), um Schreib/Lese-Attribute der OU sicher zu haben
                    # Parse Parent DN aus dem Child DN
                    $ParentDN = $CompDN.Substring($CompDN.IndexOf(",") + 1)
                    $ParentEntry = [adsi]"LDAP://$ParentDN"

                    # Check: Ist es OU oder Container?
                    if ($ParentEntry.SchemaClassName -eq "organizationalUnit") {
                        # Attribute lesen. Achtung: Wenn Attribut leer, wirft ADSI keinen Fehler, sondern gibt null zurück.
                        # Location (City) -> Attribut 'l'
                        if ($ParentEntry.Properties.Contains("l")) {
                            $FinalLocation = $ParentEntry.Properties["l"][0]
                        }
                        # Country -> Attribut 'co' (Country-Name) oder 'c' (Country-Code). Wir nehmen 'co' wie meist üblich für lesbare Namen.
                        if ($ParentEntry.Properties.Contains("co")) {
                            $FinalCountry = $ParentEntry.Properties["co"][0]
                        }
                        # LocationAbbreviation -> Attribut 'name'
                        if ($ParentEntry.Properties.Contains("name")) {
                            $FinalLocAbbrev = $ParentEntry.Properties["name"][0]
                        }
                    } else {
                        Write-Log "Parent ist keine OU ($($ParentEntry.SchemaClassName)). Setze Werte auf null."
                    }

                } else {
                    Write-Log "Kein Computer-Objekt im GC gefunden für: $hostname" "WARN"
                }
            } catch {
                Write-Log "AD Fehler bei Suche nach $hostname : $($_.Exception.Message)" "ERROR"
            }
        }

        # Output Objekt bauen
        $Obj = [PSCustomObject]@{
            Hostname             = $hostname
            IPAddress            = $FinalIP
            Location             = $FinalLocation
            Country              = $FinalCountry
            LocationAbbreviation = $FinalLocAbbrev
        }

        $Results.Add($Obj)
    }

    # Export
    Write-Log "Exportiere Ergebnisse nach $OutputFile"
    $Results | Export-Csv -Path $OutputFile -NoTypeInformation -Delimiter ";" -Encoding UTF8

    Write-Log "Script erfolgreich beendet."

} catch {
    Write-Log "Kritischer Fehler im Script: $($_.Exception.Message)" "ERROR"
    exit 1
}