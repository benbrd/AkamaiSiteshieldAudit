# 🛡️ Akamai SiteShield Audit Script

PowerShell script for auditing and analyzing Akamai SiteShield protection across your properties.

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Parameters](#parameters)
- [Examples](#examples)
- [Output Formats](#output-formats)
- [Sample Output](#sample-output)
- [Troubleshooting](#troubleshooting)
- [Author](#author)

## 🎯 Overview

This script provides comprehensive auditing capabilities for Akamai SiteShield configurations:

- ✅ **Audit Mode** (default): Shows both protected and unprotected properties
- 🛡️ **Protected Mode**: Lists only properties with SiteShield protection
- ⚠️ **Unprotected Mode**: Identifies properties without SiteShield protection
- 📊 **Detailed Statistics**: Properties and hostnames counts per SiteShield map
- 💾 **Multiple Export Formats**: CSV and JSON output support
- 🔄 **Parallel Processing**: Optimized performance with concurrent API calls
- 🎭 **Environment Support**: Both Production and Staging environments

## 📦 Prerequisites

- **PowerShell 7.0+** - Required for parallel processing support
- **Akamai PowerShell Module v2** - Install via PowerShell command
- **Valid .edgerc credentials** - With PAPI READ-WRITE access

### Installing Akamai PowerShell Module

```powershell
# Install Akamai PowerShell module
Install-Module Akamai
```

## 🚀 Installation

1. Download the script:
```powershell
# Clone or download the script
```

2. Ensure your `.edgerc` file is configured:
```ini
[default]
client_secret = your_client_secret
host = your_host.luna.akamaiapis.net
access_token = your_access_token
client_token = your_client_token
```

3. Run the script:
```powershell
.\Get-AkamaiSiteshieldAudit.ps1
```

## 💻 Usage

### Basic Syntax

```powershell
.\Get-AkamaiSiteshieldAudit.ps1 [-SiteshieldMapDNSName <string>] [-Staging] 
                                 [-ShowProtected] [-ShowUnprotected] 
                                 [-OutputFile <string>] [-EdgeRCFile <string>] 
                                 [-Section <string>] [-AccountSwitchKey <string>]
```

## 🔧 Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `SiteshieldMapDNSName` | String | No | - | Specific SiteShield map to analyze |
| `Staging` | Switch | No | False | Analyze Staging environment |
| `ShowProtected` | Switch | No | False | Show only protected properties |
| `ShowUnprotected` | Switch | No | False | Show only unprotected properties |
| `OutputFile` | String | No | - | Export path (.csv or .json) |
| `EdgeRCFile` | String | No | `~\.edgerc` | Path to credentials file |
| `Section` | String | No | `default` | Section in .edgerc file |
| `AccountSwitchKey` | String | No | - | Account switch key |

## 📚 Examples

### Example 1: Default Audit Mode (Production)
```powershell
.\Get-AkamaiSiteshieldAudit.ps1
```
Shows both protected and unprotected properties in Production.

### Example 2: Audit with JSON Export
```powershell
.\Get-AkamaiSiteshieldAudit.ps1 -OutputFile "audit-report.json"
```
Exports: `audit-report_Audit_2025-01-08_14-30-45.json`

### Example 3: Show Only Protected Properties
```powershell
.\Get-AkamaiSiteshieldAudit.ps1 -ShowProtected -OutputFile "protected.csv"
```
Exports: `protected_Protected_2025-01-08_14-30-45.csv`

### Example 4: Find Unprotected Properties in Staging
```powershell
.\Get-AkamaiSiteshieldAudit.ps1 -ShowUnprotected -Staging
```
Identifies vulnerable properties in Staging environment.

### Example 5: Analyze Specific SiteShield Map
```powershell
.\Get-AkamaiSiteshieldAudit.ps1 -SiteshieldMapDNSName "ss.example.akadns.net" -OutputFile "specific-map.json"
```

## 📤 Output Formats

### File Naming Convention

Files are automatically named with mode and timestamp:

```
{basename}_{Mode}_{Timestamp}.{extension}
{basename}_{Mode}_STAGING_{Timestamp}.{extension}  # When using -Staging
```

**Examples:**
- `report_Audit_2025-01-08_14-30-45.json`
- `report_Protected_STAGING_2025-01-08_15-45-30.csv`
- `report_Unprotected_2025-01-08_16-20-15.json`

### CSV Structure (Audit Mode)

| Status | SiteShieldMap | PropertyName | Hostnames |
|--------|---------------|--------------|-----------|
| PROTECTED | ss.example.akadns.net | www-property | www.example.com,api.example.com |
| UNPROTECTED | N/A | legacy-property | old.example.com |

### JSON Structure (Audit Mode)

```json
{
  "Protected": [
    {
      "ssmapName": "ss.example.akadns.net",
      "property": [
        {
          "propertyName": "www-property",
          "hostnames": ["www.example.com", "api.example.com"]
        }
      ]
    }
  ],
  "Unprotected": [
    {
      "ssmapName": "UNPROTECTED",
      "property": [
        {
          "propertyName": "legacy-property",
          "hostnames": ["old.example.com"]
        }
      ]
    }
  ]
}
```

## 🎨 Sample Output

### Audit Mode Output (with colors)

<pre>
<span style="color: cyan;"><b>=== Analyzing properties WITH SiteShield ===</b></span>
Step 1/3: Retrieving SiteShield maps...
SiteShield maps found: 2
Step 2/3: Searching for protected properties...
Protected properties identified: 45
Step 3/3: Retrieving hostnames for protected properties...
Protected hostnames identified: 187

<span style="color: cyan;"><b>=== Analyzing properties WITHOUT SiteShield ===</b></span>
Step 1/2: Identifying unprotected properties...
Unprotected properties found: 5
Step 2/2: Retrieving hostnames for unprotected properties...
Unprotected hostnames identified: 12

<span style="color: magenta;">╔═══════════════════════════════════════════╗
║       SITESHIELD AUDIT REPORT             ║
╚═══════════════════════════════════════════╝</span>

<span style="color: green;">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    PROPERTIES PROTECTED BY SITESHIELD     
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span>

  <span style="color: cyan;">▸ Map: ss.example1.akadns.net</span>
    • Properties: 30
    • Hostnames: 125

  <span style="color: cyan;">▸ Map: ss.example2.akadns.net</span>
    • Properties: 15
    • Hostnames: 62

  <span style="color: green;">✓ TOTAL PROTECTED:</span>
    <span style="color: green;">• Properties: 45</span>
    <span style="color: green;">• Hostnames: 187</span>

<span style="color: red;">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    UNPROTECTED PROPERTIES (EXPOSED)        
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span>

  <span style="color: yellow;">⚠ WARNING: Properties without SiteShield protection detected!</span>
    <span style="color: red;">• Exposed properties: 5</span>
    <span style="color: red;">• Exposed hostnames: 12</span>

<span style="color: magenta;">━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
           GLOBAL OVERVIEW                  
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━</span>

  Total active properties: 50
  Total hostnames: 199
  <span style="color: green;">Protection rate: 90.0%</span>

<span style="color: green;">✓ Script completed successfully</span>
</pre>

### Protected Mode Output

<pre>
<span style="color: cyan;"><b>=== Analyzing properties WITH SiteShield ===</b></span>
Step 1/3: Retrieving SiteShield maps...
SiteShield maps found: 2
Step 2/3: Searching for protected properties...
Protected properties identified: 45
Step 3/3: Retrieving hostnames for protected properties...
Protected hostnames identified: 187

<span style="color: yellow;">=========================================
Statistics per SiteShield Map:
=========================================</span>

<span style="color: cyan;">Map: ss.example1.akadns.net</span>
  - Protected properties: 30
  - Unique hostnames: 125

<span style="color: cyan;">Map: ss.example2.akadns.net</span>
  - Protected properties: 15
  - Unique hostnames: 62

<span style="color: yellow;">=========================================</span>
<span style="color: green;">GLOBAL TOTAL:</span>
  <span style="color: green;">- Protected properties: 45</span>
  <span style="color: green;">- Unique protected hostnames: 187</span>
<span style="color: yellow;">=========================================</span>

<span style="color: green;">✓ Script completed successfully</span>
</pre>

### Unprotected Mode Output

<pre>
<span style="color: cyan;"><b>=== Analyzing properties WITHOUT SiteShield ===</b></span>
Step 1/2: Identifying unprotected properties...
Unprotected properties found: 5
Step 2/2: Retrieving hostnames for unprotected properties...
Unprotected hostnames identified: 12

<span style="color: yellow;">=========================================
Statistics:
=========================================</span>
<span style="color: cyan;">Properties WITHOUT SiteShield: 5</span>
<span style="color: cyan;">Unique hostnames WITHOUT SiteShield: 12</span>
<span style="color: yellow;">=========================================</span>

propertyName        hostnames
------------        ---------
legacy-app          old.example.com,legacy.example.com
test-site           test.example.com
dev-environment     dev.example.com,staging.example.com
marketing-site      promo.example.com
archive-portal      archive.example.com

<span style="color: green;">✓ Script completed successfully</span>
</pre>

### Color Legend

- <span style="color: cyan;">**Cyan**</span>: Section headers and informational messages
- <span style="color: green;">**Green**</span>: Success messages and protected properties
- <span style="color: yellow;">**Yellow**</span>: Warnings and statistics
- <span style="color: red;">**Red**</span>: Errors and unprotected properties alerts
- <span style="color: magenta;">**Magenta**</span>: Report titles and separators

## 🔍 Troubleshooting

### Common Issues

#### Issue: "Module Akamai not found"
```powershell
# Solution: Install the Akamai PowerShell module
Install-Module Akamai
```

#### Issue: "Authentication failed"
```powershell
# Solution: Verify your .edgerc credentials
# Check that the file exists and has correct permissions
Test-Path ~/.edgerc
```

#### Issue: "No SiteShield maps found"
```powershell
# Solution: Verify API permissions
# Ensure your API client has PAPI READ-WRITE access
```

#### Issue: Script runs slowly
```powershell
# The script processes properties in parallel (4 concurrent threads)
# Large property counts will take time - this is normal
# You can monitor progress via the progress bars
```


## 📝 Notes

- **Performance**: The script uses parallel processing (4 concurrent threads) for optimal performance
- **Rate Limiting**: Respects Akamai API rate limits automatically
- **Large Environments**: For accounts with 100+ properties, expect few minutes execution time
- **Staging vs Production**: Always verify you're analyzing the correct environment
- **Data Accuracy**: Results reflect the state at execution time

## 📄 License

[Apache License 2](https://choosealicense.com/licenses/apache-2.0/).

## 🔗 Related Resources

- [Akamai SiteShield Documentation](https://techdocs.akamai.com/siteshield/docs)
- [Akamai CLI Documentation](https://developer.akamai.com/cli)
- [PowerShell 7+ Download](https://github.com/PowerShell/PowerShell)

---

[![Made with love by](https://img.shields.io/badge/Made%20with%20%E2%9D%A4%EF%B8%8F-by%20Benjamin%20Brouard-EF4135?labelColor=0055A4)](https://www.linkedin.com/in/benjaminbrouard/)