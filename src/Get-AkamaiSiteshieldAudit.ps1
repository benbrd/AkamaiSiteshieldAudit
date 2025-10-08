<#
.SYNOPSIS
    Akamai SiteShield Audit and Analysis Script

.DESCRIPTION
    This script analyzes Akamai properties to identify which are protected by SiteShield 
    and which are not. It provides comprehensive reporting capabilities with support for 
    multiple output formats (CSV, JSON) and analysis modes (Audit, Protected only, Unprotected only).

.AUTHOR
    Benjamin Brouard

.VERSION
    1.1

.DATE
    2025-10-08

.NOTES
    Purpose:
    - Audit all properties to identify SiteShield protection status
    - List properties and hostnames associated with each SiteShield map
    - Identify unprotected properties that may need SiteShield protection
    - Generate detailed reports in CSV or JSON format
    - Support both Production and Staging environments

    Requirements:
    - Akamai PowerShell module
    - Valid .edgerc credentials with PAPI READ-WRITE access
    - PowerShell 7.0 or higher (for parallel processing support)

    Features:
    - Three analysis modes: Audit (default), ShowProtected, ShowUnprotected
    - Parallel processing for improved performance
    - Comprehensive error handling and logging
    - Automatic file naming with timestamp and mode identification
    - Progress bars for long-running operations

.PARAMETER SiteshieldMapDNSName
    Optional. Specific SiteShield map DNS name to analyze. If not provided, analyzes all maps.

.PARAMETER Staging
    Optional. Switch to analyze Staging environment instead of Production (default).

.PARAMETER ShowProtected
    Optional. Switch to display only properties protected by SiteShield.

.PARAMETER ShowUnprotected
    Optional. Switch to display only properties without SiteShield protection.

.PARAMETER OutputFile
    Optional. Path to output file. Supports .csv and .json formats.
    File will be automatically named with mode and timestamp.

.PARAMETER EdgeRCFile
    Optional. Path to .edgerc credentials file. Default: "~\.edgerc"

.PARAMETER Section
    Optional. Section name in .edgerc file to use. Default: "default"

.PARAMETER AccountSwitchKey
    Optional. Account switch key for multi-account access.

.EXAMPLE
    .\SiteShield-Audit.ps1
    Run in default Audit mode (shows both protected and unprotected properties)

.EXAMPLE
    .\SiteShield-Audit.ps1 -ShowProtected -OutputFile "report.csv"
    Export only protected properties to CSV

.EXAMPLE
    .\SiteShield-Audit.ps1 -ShowUnprotected -Staging
    Show only unprotected properties in Staging environment

.EXAMPLE
    .\SiteShield-Audit.ps1 -SiteshieldMapDNSName "ss.example.akadns.net" -OutputFile "report.json"
    Analyze specific SiteShield map and export to JSON

.LINK
    https://techdocs.akamai.com/site-shield/docs/welcome-site-shield
#>

Param(
    [Parameter(Mandatory=$false)] 
    [string] $SiteshieldMapDNSName,
    
    [Parameter(Mandatory=$false)] 
    [switch] $Staging,
    
    [Parameter(Mandatory=$false)] 
    [switch] $ShowProtected,  # Option to display only properties with SiteShield
    
    [Parameter(Mandatory=$false)] 
    [switch] $ShowUnprotected,  # Option to display only properties without SiteShield
    
    [Parameter(Mandatory=$false)] 
    [string] $OutputFile,
    
    [Parameter(Mandatory=$false)] 
    [string] $EdgeRCFile = "~\.edgerc",
    
    [Parameter(Mandatory=$false)] 
    [string] $Section = "default",
    
    [Parameter(Mandatory=$false)] 
    [string] $AccountSwitchKey
)

# Import Akamai module if needed
if(!(Get-Module Akamai)) {
    Import-Module Akamai -DisableNameCheck
}

# Set error action preference to stop on errors
$ErrorActionPreference = "Stop"

# Initialize error log
$script:ErrorLog = [System.Collections.ArrayList]::new()

# Function to log errors
function Write-ErrorLog {
    param(
        [string]$Message,
        [string]$Context,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    
    $errorEntry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Context = $Context
        Message = $Message
        Exception = if ($ErrorRecord) { $ErrorRecord.Exception.Message } else { $null }
        StackTrace = if ($ErrorRecord) { $ErrorRecord.ScriptStackTrace } else { $null }
    }
    
    [void]$script:ErrorLog.Add($errorEntry)
    Write-Warning "[$($errorEntry.Timestamp)] $Context - $Message"
}

try {
    # Validation: -ShowProtected and -ShowUnprotected cannot be used together
    if ($ShowProtected -and $ShowUnprotected) {
        Write-Error "The -ShowProtected and -ShowUnprotected options cannot be used together. Use neither to see both (audit mode)."
        exit
    }
    
    # Determine the mode: Audit (default), ShowProtected, or ShowUnprotected
    $AuditMode = -not $ShowProtected -and -not $ShowUnprotected
    
    # ====================================================================
    # PART 1: Retrieve properties with SiteShield
    # ====================================================================
    
    # Declare variables that will be used in different parts
    $ProtectedResult = $null
    $UnprotectedResult = @()
    $totalUnprotectedHostnames = 0
    $FinalList = $null
    
    # Execute this part if: ShowProtected mode OR Audit mode (default)
    if ($ShowProtected -or $AuditMode) {
        Write-Host -ForegroundColor Cyan "=== Analyzing properties WITH SiteShield ==="
        
        # Step 1: Retrieve SiteShield maps
        Write-Host "Step 1/3: Retrieving SiteShield maps..."
        
        # Determine which SiteShield maps to analyze
        if ($SiteshieldMapDNSName) {
            $siteshieldMaps = @($SiteshieldMapDNSName)
        }
        else {
            # Retrieve all available SiteShield maps
            try {
                $siteshieldMaps = Get-SiteShieldMap -EdgeRCFile $EdgeRCFile -Section $Section -AccountSwitchKey $AccountSwitchKey | 
                                  Select-Object -ExpandProperty ruleName -Unique
                
                if (-not $siteshieldMaps) {
                    Write-ErrorLog -Message "No SiteShield maps found" -Context "SiteShield Map Retrieval"
                    throw "No SiteShield maps found in the account"
                }
            }
            catch {
                Write-ErrorLog -Message "Failed to retrieve SiteShield maps" -Context "API Call" -ErrorRecord $_
                throw
            }
        }
        
        Write-Host "SiteShield maps found: $($siteshieldMaps.Count)"
        Write-Host "Step 2/3: Searching for protected properties..."
        
        $counter = 0
        $FinalList = [System.Collections.ArrayList]::new()
        
        # Loop through each SiteShield map
        foreach($siteshieldMap in $siteshieldMaps) {
            $counter++
            $percentComplete = ($counter / $siteshieldMaps.count) * 100
            Write-Progress -Activity "$($siteshieldMaps.count) SiteShield map(s) to process" `
                          -Status "$counter of $($siteshieldMaps.count) - Processing: $siteshieldMap" `
                          -PercentComplete $percentComplete
            
            # Search for all properties using this SiteShield map
            try {
                $bulkResults = New-BulkSearch -Match "$..behaviors[?(@.name == `"siteShield`")].options.ssmap[?(@.value == `"$siteshieldMap`")]" `
                                             -Synchronous `
                                             -EdgeRCFile $EdgeRCFile `
                                             -Section $Section `
                                             -AccountSwitchKey $AccountSwitchKey
            }
            catch {
                Write-ErrorLog -Message "Failed to search properties for map: $siteshieldMap" -Context "Bulk Search" -ErrorRecord $_
                # Continue with next map instead of failing completely
                continue
            }    
            
            if ($bulkResults.results) {
                # Filter active properties first to reduce API calls
                $activeProperties = $bulkResults.results | Where-Object {
                    if($Staging) {
                        $_.stagingStatus -eq "ACTIVE"
                    } else {
                        $_.productionStatus -eq "ACTIVE"
                    }
                }
                
                if ($activeProperties) {
                    # Process results in parallel with throttle limit
                    $data = $activeProperties | ForEach-Object -ThrottleLimit 4 -Parallel {
                        try {
                            # Retrieve hostnames for this property
                            $hostnamesList = Get-PropertyHostname -PropertyId $_.propertyId `
                                                                  -PropertyVersion $_.propertyVersion `
                                                                  -EdgeRCFile $using:EdgeRCFile `
                                                                  -Section $using:Section `
                                                                  -AccountSwitchKey $using:AccountSwitchKey | 
                                            Select-Object -ExpandProperty cnameFrom -Unique
                            
                            # Create custom object with the data
                            [PSCustomObject]@{
                                propertyName = $_.propertyName
                                hostnames = $hostnamesList
                            }
                        }
                        catch {
                            # Log error but continue processing other properties
                            Write-Warning "Failed to get hostnames for property: $($_.propertyName)"
                            
                            # Return property with error indicator
                            [PSCustomObject]@{
                                propertyName = "$($_.propertyName) [ERROR]"
                                hostnames = @()
                            }
                        }
                    }
                }
                else {
                    $data = $null
                }
            }
            else {
                # No properties found for this map
                $data = [PSCustomObject]@{
                    propertyName = "<EMPTY>"
                    hostnames = "<EMPTY>"
                }
            }
            
            # Add data to final list
            if ($data) {
                $CustomData2 = [PSCustomObject]@{
                    ssmapName = $siteshieldMap
                    property = $data
                }
                $FinalList.Add($CustomData2) | Out-Null
            }
        }
        
        # Clear progress bar
        Write-Progress -Activity "Processing completed" -Completed
        
        # Count protected properties
        $totalProtectedProps = ($FinalList | ForEach-Object { $_.property } | Where-Object { $_.propertyName -ne "<EMPTY>" } | Measure-Object).Count
        Write-Host "Protected properties identified: $totalProtectedProps"
        
        Write-Host "Step 3/3: Retrieving hostnames for protected properties..."
        
        # Format results for display
        $ProtectedResult = $FinalList | 
                          Select-Object -ExpandProperty property -Property ssmapName |
                          Select-Object ssmapName, 
                                       @{N='propertyName'; E={$_.propertyName}}, 
                                       @{N='hostnames'; E={$_.hostnames -join ','}}
        
        # Count protected hostnames
        $totalProtectedHosts = ($FinalList | 
                               ForEach-Object { $_.property } | 
                               Where-Object { $_.propertyName -ne "<EMPTY>" } |
                               ForEach-Object { $_.hostnames } | 
                               Where-Object { $_ -ne $null -and $_ -ne "<EMPTY>" } | 
                               Select-Object -Unique | Measure-Object).Count
        
        Write-Host "Protected hostnames identified: $totalProtectedHosts"
    }
    
    # ====================================================================
    # PART 2: Retrieve properties WITHOUT SiteShield
    # ====================================================================
    
    # Execute this part if: ShowUnprotected mode OR Audit mode (default)
    if (($ShowUnprotected -or $AuditMode) -and -not $SiteshieldMapDNSName) {
        Write-Host -ForegroundColor Cyan "=== Analyzing properties WITHOUT SiteShield ==="
        
        # Step 1: Identify unprotected properties (by comparing all properties with protected ones)
        Write-Host "Step 1/2: Identifying unprotected properties..."
        
        # First, retrieve all properties that HAVE SiteShield
        try {
            $protectedSearch = New-BulkSearch -Match "$..behaviors[?(@.name ==`"siteShield`")]" `
                                             -Synchronous `
                                             -EdgeRCFile $EdgeRCFile `
                                             -Section $Section `
                                             -AccountSwitchKey $AccountSwitchKey
        }
        catch {
            Write-ErrorLog -Message "Failed to search for protected properties" -Context "Bulk Search Protected" -ErrorRecord $_
            throw
        }
        
        # Create a HashSet to store keys of protected properties
        $protectedKeys = [System.Collections.Generic.HashSet[string]]::new()
        
        if ($protectedSearch.results) {
            foreach ($prop in $protectedSearch.results) {
                # Determine whether to analyze Staging or Production
                $isActive = if($Staging) {
                    $prop.stagingStatus -eq "ACTIVE"
                } else {
                    $prop.productionStatus -eq "ACTIVE"
                }
                
                if ($isActive) {
                    # Create unique key: propertyId_propertyVersion
                    $key = "$($prop.propertyId)_$($prop.propertyVersion)"
                    [void]$protectedKeys.Add($key)
                }
            }
        }
        
        # Retrieve ALL active properties
        try {
            $allPropertiesSearch = New-BulkSearch -Match "$..behaviors[?(@.name ==`"cpCode`")]" `
                                                 -Synchronous `
                                                 -EdgeRCFile $EdgeRCFile `
                                                 -Section $Section `
                                                 -AccountSwitchKey $AccountSwitchKey
        }
        catch {
            Write-ErrorLog -Message "Failed to retrieve all active properties" -Context "Bulk Search All" -ErrorRecord $_
            throw
        }
        
        if ($allPropertiesSearch.results) {
            # Filter to keep only active properties that are NOT protected
            $unprotectedProperties = $allPropertiesSearch.results | Where-Object {
                # Determine if property is active
                $isActive = if($Staging) {
                    $_.stagingStatus -eq "ACTIVE"
                } else {
                    $_.productionStatus -eq "ACTIVE"
                }
                
                if ($isActive) {
                    # Check if this property is NOT in the protected list
                    $key = "$($_.propertyId)_$($_.propertyVersion)"
                    -not $protectedKeys.Contains($key)
                } else {
                    $false
                }
            }
            
            $totalProperties = ($unprotectedProperties | Measure-Object).Count
            Write-Host "Unprotected properties found: $totalProperties"
            
            if ($totalProperties -gt 0) {
                # Step 2: Retrieve hostnames for unprotected properties
                Write-Host "Step 2/2: Retrieving hostnames for unprotected properties..."
                
                # Counter for progress bar (using thread-safe hashtable)
                $progressCounter = [hashtable]::Synchronized(@{Value = 0})
                
                # Process unprotected properties in parallel
                $data = $unprotectedProperties | ForEach-Object -ThrottleLimit 4 -Parallel {
                    try {
                        # Retrieve hostnames for this unprotected property
                        $hostnamesList = Get-PropertyHostname -PropertyId $_.propertyId `
                                                              -PropertyVersion $_.propertyVersion `
                                                              -EdgeRCFile $using:EdgeRCFile `
                                                              -Section $using:Section `
                                                              -AccountSwitchKey $using:AccountSwitchKey | 
                                        Select-Object -ExpandProperty cnameFrom -Unique
                        
                        # Update progress bar (thread-safe)
                        $counter = ++($using:progressCounter).Value
                        $percentComplete = ($counter / $using:totalProperties) * 100
                        Write-Progress -Activity "$($using:totalProperties) propertie(s) without SiteShield to process" `
                                      -Status "$counter of $($using:totalProperties) - Processing: $($_.propertyName)" `
                                      -PercentComplete $percentComplete
                        
                        # Return object with property information
                        [PSCustomObject]@{
                            propertyName = $_.propertyName
                            hostnames = $hostnamesList
                            hostnameCount = ($hostnamesList | Measure-Object).Count
                        }
                    }
                    catch {
                        # Log error but continue processing
                        Write-Warning "Failed to get hostnames for unprotected property: $($_.propertyName)"
                        
                        # Return property with error indicator
                        [PSCustomObject]@{
                            propertyName = "$($_.propertyName) [ERROR]"
                            hostnames = @()
                            hostnameCount = 0
                        }
                    }
                }
                
                # Clear progress bar
                Write-Progress -Activity "Processing completed" -Completed
                
                # Filter null results
                $unprotectedList = $data | Where-Object { $_ -ne $null }
                
                # Calculate total number of unique hostnames
                $allUnprotectedHostnames = $unprotectedList | 
                               ForEach-Object { $_.hostnames } | 
                               Where-Object { $_ -ne $null } | 
                               Select-Object -Unique
                $totalUnprotectedHostnames = ($allUnprotectedHostnames | Measure-Object).Count
                
                Write-Host "Unprotected hostnames identified: $totalUnprotectedHostnames"
                
                # Format results
                $UnprotectedResult = $unprotectedList | 
                          Select-Object @{N='propertyName'; E={$_.propertyName}},
                                       @{N='hostnames'; E={$_.hostnames -join ','}}
            }
            else {
                Write-Host -ForegroundColor Green "All active properties are protected by SiteShield!"
                $UnprotectedResult = @()
                $totalUnprotectedHostnames = 0
            }
        }
        else {
            Write-Host -ForegroundColor Green "No active properties found!"
            $UnprotectedResult = @()
            $totalUnprotectedHostnames = 0
        }
    }
    
    # ====================================================================
    # PART 3: Display statistics and results
    # ====================================================================
    
    # Determine which result to display based on mode
    if ($AuditMode -and -not $SiteshieldMapDNSName) {
        # AUDIT MODE (DEFAULT): Display both types of results
        Write-Host -ForegroundColor Magenta "`n╔═══════════════════════════════════════════╗"
        Write-Host -ForegroundColor Magenta "║       SITESHIELD AUDIT REPORT             ║"
        Write-Host -ForegroundColor Magenta "╚═══════════════════════════════════════════╝`n"
        
        # Section 1: PROTECTED Properties
        Write-Host -ForegroundColor Green "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        Write-Host -ForegroundColor Green "    PROPERTIES PROTECTED BY SITESHIELD     "
        Write-Host -ForegroundColor Green "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n"
        
        # Statistics per SiteShield map
        foreach ($mapData in $FinalList) {
            $mapName = $mapData.ssmapName
            
            # Count properties (exclude empty entries)
            $properties = $mapData.property | Where-Object { $_.propertyName -ne "<EMPTY>" }
            $propertyCount = ($properties | Measure-Object).Count
            
            # Count unique hostnames for this map
            $uniqueHostnames = $properties | 
                              ForEach-Object { $_.hostnames } | 
                              Where-Object { $_ -ne $null -and $_ -ne "<EMPTY>" } | 
                              Select-Object -Unique
            $hostnameCount = ($uniqueHostnames | Measure-Object).Count
            
            Write-Host -ForegroundColor Cyan "  ▸ Map: $mapName"
            Write-Host "    • Properties: $propertyCount"
            Write-Host "    • Hostnames: $hostnameCount"
            Write-Host ""
        }
        
        # Totals for protected properties
        $totalProtectedProperties = ($FinalList | ForEach-Object { $_.property } | Where-Object { $_.propertyName -ne "<EMPTY>" } | Measure-Object).Count
        $allProtectedHostnames = $FinalList | 
                       ForEach-Object { $_.property } | 
                       Where-Object { $_.propertyName -ne "<EMPTY>" } |
                       ForEach-Object { $_.hostnames } | 
                       Where-Object { $_ -ne $null -and $_ -ne "<EMPTY>" } | 
                       Select-Object -Unique
        $totalProtectedHostnames = ($allProtectedHostnames | Measure-Object).Count
        
        Write-Host -ForegroundColor Green "  ✓ TOTAL PROTECTED:"
        Write-Host -ForegroundColor Green "    • Properties: $totalProtectedProperties"
        Write-Host -ForegroundColor Green "    • Hostnames: $totalProtectedHostnames`n"
        
        # Section 2: UNPROTECTED Properties
        Write-Host -ForegroundColor Red "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        Write-Host -ForegroundColor Red "    UNPROTECTED PROPERTIES (EXPOSED)        "
        Write-Host -ForegroundColor Red "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n"
        
        if ($UnprotectedResult -and $UnprotectedResult.count -gt 0) {
            Write-Host -ForegroundColor Yellow "  ⚠ WARNING: Properties without SiteShield protection detected!"
            Write-Host -ForegroundColor Red "    • Exposed properties: $($UnprotectedResult.count)"
            Write-Host -ForegroundColor Red "    • Exposed hostnames: $totalUnprotectedHostnames`n"
        }
        else {
            Write-Host -ForegroundColor Green "  ✓ No unprotected properties detected`n"
        }
        
        # Section 3: Global overview
        Write-Host -ForegroundColor Magenta "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        Write-Host -ForegroundColor Magenta "           GLOBAL OVERVIEW                  "
        Write-Host -ForegroundColor Magenta "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n"
        
        $totalProperties = $totalProtectedProperties + $UnprotectedResult.count
        $totalHostnames = $totalProtectedHostnames + $totalUnprotectedHostnames
        $protectionRate = if ($totalProperties -gt 0) { 
            [math]::Round(($totalProtectedProperties / $totalProperties) * 100, 2) 
        } else { 0 }
        
        Write-Host "  Total active properties: $totalProperties"
        Write-Host "  Total hostnames: $totalHostnames"
        Write-Host -ForegroundColor $(if ($protectionRate -ge 80) { "Green" } elseif ($protectionRate -ge 50) { "Yellow" } else { "Red" }) "  Protection rate: $protectionRate%"
        Write-Host ""
        
        # Create combined result for export with consistent structure
        $CombinedResult = [PSCustomObject]@{
            Protected = $FinalList
            Unprotected = if ($UnprotectedResult -and $UnprotectedResult.count -gt 0) {
                # Group unprotected properties under a single "Unprotected" map structure
                @([PSCustomObject]@{
                    ssmapName = "UNPROTECTED"
                    property = $UnprotectedResult | ForEach-Object {
                        [PSCustomObject]@{
                            propertyName = $_.propertyName
                            hostnames = if ($_.hostnames -is [string]) { 
                                $_.hostnames -split ',' 
                            } else { 
                                $_.hostnames 
                            }
                        }
                    }
                })
            } else {
                @()
            }
        }
        
        $Result = $CombinedResult
        
    }
    elseif ($ShowProtected -or $SiteshieldMapDNSName) {
        # SHOWPROTECTED MODE: Display only protected properties
        Write-Host -ForegroundColor Yellow "`n========================================="
        Write-Host -ForegroundColor Yellow "Statistics per SiteShield Map:"
        Write-Host -ForegroundColor Yellow "=========================================`n"
        
        foreach ($mapData in $FinalList) {
            $mapName = $mapData.ssmapName
            
            # Count properties (exclude empty entries)
            $properties = $mapData.property | Where-Object { $_.propertyName -ne "<EMPTY>" }
            $propertyCount = ($properties | Measure-Object).Count
            
            # Count unique hostnames for this map
            $uniqueHostnames = $properties | 
                              ForEach-Object { $_.hostnames } | 
                              Where-Object { $_ -ne $null -and $_ -ne "<EMPTY>" } | 
                              Select-Object -Unique
            $hostnameCount = ($uniqueHostnames | Measure-Object).Count
            
            Write-Host -ForegroundColor Cyan "Map: $mapName"
            Write-Host "  - Protected properties: $propertyCount"
            Write-Host "  - Unique hostnames: $hostnameCount"
            Write-Host ""
        }
        
        # Calculate global totals
        $totalProperties = ($FinalList | ForEach-Object { $_.property } | Where-Object { $_.propertyName -ne "<EMPTY>" } | Measure-Object).Count
        $allHostnames = $FinalList | 
                       ForEach-Object { $_.property } | 
                       Where-Object { $_.propertyName -ne "<EMPTY>" } |
                       ForEach-Object { $_.hostnames } | 
                       Where-Object { $_ -ne $null -and $_ -ne "<EMPTY>" } | 
                       Select-Object -Unique
        $totalHostnames = ($allHostnames | Measure-Object).Count
        
        Write-Host -ForegroundColor Yellow "========================================="
        Write-Host -ForegroundColor Green "GLOBAL TOTAL:"
        Write-Host -ForegroundColor Green "  - Protected properties: $totalProperties"
        Write-Host -ForegroundColor Green "  - Unique protected hostnames: $totalHostnames"
        Write-Host -ForegroundColor Yellow "=========================================`n"
        
        $Result = $ProtectedResult
    }
    else {
        # SHOWUNPROTECTED MODE: Display only unprotected properties
        Write-Host -ForegroundColor Yellow "`n========================================="
        Write-Host -ForegroundColor Yellow "Statistics:"
        Write-Host -ForegroundColor Yellow "========================================="
        Write-Host -ForegroundColor Cyan "Properties WITHOUT SiteShield: $($UnprotectedResult.count)"
        Write-Host -ForegroundColor Cyan "Unique hostnames WITHOUT SiteShield: $totalUnprotectedHostnames"
        Write-Host -ForegroundColor Yellow "=========================================`n"
        
        $Result = $UnprotectedResult
    }
    
    # Display detailed results in console (except in Audit mode where it's already done)
    if (-not $AuditMode) {
        $Result | Format-Table -AutoSize
    }
    
    # ====================================================================
    # PART 4: Export results
    # ====================================================================
    
    # Export to file if requested
    if ($OutputFile) {
        # Generate timestamp
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        
        # Determine mode suffix
        $modeSuffix = if ($AuditMode) {
            "Audit"
        } elseif ($ShowProtected -or $SiteshieldMapDNSName) {
            "Protected"
        } else {
            "Unprotected"
        }
        
        # Add Staging suffix if applicable
        if ($Staging) {
            $modeSuffix = "${modeSuffix}_STAGING"
        }
        
        # Determine export format (CSV or JSON)
        if ($OutputFile -like "*.csv") {
            # Extract base name without extension
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputFile)
            $directory = [System.IO.Path]::GetDirectoryName($OutputFile)
            
            # Build new filename
            if ($directory) {
                $newOutputFile = Join-Path $directory "${baseName}_${modeSuffix}_${timestamp}.csv"
            } else {
                $newOutputFile = "${baseName}_${modeSuffix}_${timestamp}.csv"
            }
            
            # CSV export - need to flatten data for Audit mode
            if ($AuditMode) {
                try {
                    # In Audit mode, combine protected and unprotected results
                    $csvData = [System.Collections.ArrayList]::new()
                    
                    # Add protected properties
                    foreach ($item in $ProtectedResult) {
                        $csvData.Add([PSCustomObject]@{
                            Status = "PROTECTED"
                            SiteShieldMap = $item.ssmapName
                            PropertyName = $item.propertyName
                            Hostnames = $item.hostnames
                        }) | Out-Null
                    }
                    
                    # Add unprotected properties
                    foreach ($item in $UnprotectedResult) {
                        $csvData.Add([PSCustomObject]@{
                            Status = "UNPROTECTED"
                            SiteShieldMap = "N/A"
                            PropertyName = $item.propertyName
                            Hostnames = $item.hostnames
                        }) | Out-Null
                    }
                    
                    $csvData | Export-Csv -Path $newOutputFile -NoTypeInformation -Encoding UTF8
                }
                catch {
                    Write-ErrorLog -Message "Failed to export CSV in Audit mode" -Context "CSV Export" -ErrorRecord $_
                    throw
                }
            }
            else {
                try {
                    # For ShowProtected or ShowUnprotected mode, export directly
                    $Result | Export-Csv -Path $newOutputFile -NoTypeInformation -Encoding UTF8
                }
                catch {
                    Write-ErrorLog -Message "Failed to export CSV" -Context "CSV Export" -ErrorRecord $_
                    throw
                }
            }
            
            Write-Host -ForegroundColor Green "`nResults exported to: $newOutputFile"
        }
        else {
            # JSON export by default
            # Extract base name without extension
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputFile)
            $directory = [System.IO.Path]::GetDirectoryName($OutputFile)
            $extension = [System.IO.Path]::GetExtension($OutputFile)
            
            # If no extension, default to .json
            if (-not $extension) {
                $extension = ".json"
            }
            
            # Build new filename
            if ($directory) {
                $newOutputFile = Join-Path $directory "${baseName}_${modeSuffix}_${timestamp}${extension}"
            } else {
                $newOutputFile = "${baseName}_${modeSuffix}_${timestamp}${extension}"
            }
            
            # Export based on mode
            if ($AuditMode) {
                try {
                    $Result | ConvertTo-Json -Depth 10 | Out-File $newOutputFile -Encoding UTF8
                }
                catch {
                    Write-ErrorLog -Message "Failed to export JSON in Audit mode" -Context "JSON Export" -ErrorRecord $_
                    throw
                }
            }
            elseif ($ShowUnprotected) {
                try {
                    $Result | ConvertTo-Json -Depth 10 | Out-File $newOutputFile -Encoding UTF8
                }
                catch {
                    Write-ErrorLog -Message "Failed to export JSON for unprotected properties" -Context "JSON Export" -ErrorRecord $_
                    throw
                }
            }
            else {
                try {
                    $FinalList | ConvertTo-Json -Depth 10 | Out-File $newOutputFile -Encoding UTF8
                }
                catch {
                    Write-ErrorLog -Message "Failed to export JSON for protected properties" -Context "JSON Export" -ErrorRecord $_
                    throw
                }
            }
            Write-Host -ForegroundColor Green "`nResults exported to: $newOutputFile"
        }        
    }
    
    # Display error summary if any errors occurred
    if ($script:ErrorLog.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "`n========================================="
        Write-Host -ForegroundColor Yellow "Error Summary:"
        Write-Host -ForegroundColor Yellow "========================================="
        Write-Host -ForegroundColor Yellow "Total errors encountered: $($script:ErrorLog.Count)"
        Write-Host -ForegroundColor Yellow "Check warnings above for details"
        Write-Host -ForegroundColor Yellow "=========================================`n"
    }
}
catch {
    $message = $_
    Write-Host -ForegroundColor Red "`n========================================="
    Write-Host -ForegroundColor Red "CRITICAL ERROR"
    Write-Host -ForegroundColor Red "=========================================`n"
    Write-Error -Message "An error occurred:`n$message"
    
    # Log the critical error
    Write-ErrorLog -Message $message.Exception.Message -Context "Script Execution" -ErrorRecord $_
    
    # Display error log if available
    if ($script:ErrorLog.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "`nError Log:"
        foreach ($logEntry in $script:ErrorLog) {
            Write-Host "  [$($logEntry.Timestamp)] $($logEntry.Context): $($logEntry.Message)"
        }
    }
    
    Write-Host -ForegroundColor DarkGreen @"

Hints to fix your issue:
----------------------------------------
• Verify that your credentials are not expired
• If you are using the [default] section of .edgerc, verify that no account_key is specified
• Verify that you have READ-WRITE access to PAPI API for your API client
• The script runs in Audit mode by default (shows both protected and unprotected properties)
• Use -ShowProtected to see only protected properties, or -ShowUnprotected to see only unprotected properties
• Check the error log above for specific failure points
• Some properties may have failed to process but the script continued (look for [ERROR] tags in results)
"@
    
    # Exit with error code
    exit 1
}
finally {
    # Cleanup and final message
    Write-Progress -Activity "Completed" -Completed
    
    if ($script:ErrorLog.Count -eq 0) {
        Write-Host -ForegroundColor Green "`n✓ Script completed successfully without errors"
    }
    else {
        Write-Host -ForegroundColor Yellow "`n⚠ Script completed with $($script:ErrorLog.Count) warning(s)/error(s)"
    }
}