<#
================================================================================
                    UNIVERSAL ACTIVE DIRECTORY USER IMPORTER
================================================================================

KIRJELDUS
---------
Skript loob ja uuendab Active Directory kasutajaid nimekirjafaili põhjal.

Skript:
- tuvastab Active Directory domeeni automaatselt;
- loob kasutajate põhi-OU;
- loob gruppide põhi-OU;
- loob osakondade OU-d;
- loob ametite põhjal turvagrupid;
- lisab sama ametiga kasutajad samasse gruppi;
- loob või uuendab kasutajakontod;
- lisab kasutaja ameti väljale Title;
- lisab kasutaja asukoha väljale Office;
- eemaldab kasutajanimest täpitähed;
- väldib sisseehitatud AD gruppidega nimekonflikte;
- kontrollib olemasolevaid objekte;
- skripti võib käivitada korduvalt;
- kuvab töö lõpus aruande.

KUIDAS KASUTADA
---------------
1. Käivita Windows PowerShell administraatorina.
2. Arvutis/serveris peab olema Active Directory PowerShell moodul ning ligipääs AD domeenile.
3. Pane mõlemad failid samasse kausta:
     AD_Users V2 (Universal).ps1
     nimekiri.csv

4. Nimekirja formaat:
     Eesnimi Perekonnanimi - Asukoht, Amet

   Näited:
     Jüri Tõnisson - Tartu, CEO
     Alice Johnson - New York, Software Engineer
     Tina King - Washington, D.C., Journalist

   Asukoht võib sisaldada komasid. Skript kasutab viimast koma asukoha ja ameti eraldamiseks.

5. Kui PowerShell blokeerib skripti käivitamise:
     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

6. Käivita:
     & ".\AD_Users V2 (Universal).ps1"

PARAMEETRID
-----------
Teise faili kasutamine:
  & ".\AD_Users V2 (Universal).ps1" -CsvPath "C:\AD\users.csv"

OU nimede muutmine:
  & ".\AD_Users V2 (Universal).ps1" -UsersOUName "Employees" -GroupsOUName "JobGroups"

Teise algparooli kasutamine:
  & ".\AD_Users V2 (Universal).ps1" -DefaultPassword "MinuParool123!"

KASUTAJANIMED
-------------
Kasutajanimi:
  eesnimi.perekonnanimi

Näited:
  Jüri Tõnisson -> juri.tonisson
  Kärt Õunapuu  -> kart.ounapuu
  Õie Põld      -> oie.pold

Kui sama kasutajanimi on juba kasutusel teise inimese poolt, lisatakse lõppu number.

GRUPID
------
Ametigrupid saavad prefiksi JOB_.

Näiteks:
  CEO               -> JOB_CEO
  Administrator     -> JOB_Administrator
  Software Engineer -> JOB_Software Engineer

Grupi sAMAccountName genereeritakse eraldi ja sellele lisatakse lühike hash, 
et vältida nimekonflikte.

================================================================================
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath = ".\nimekiri.csv",

    [Parameter(Mandatory = $false)]
    [string]$UsersOUName = "Kasutajad",

    [Parameter(Mandatory = $false)]
    [string]$GroupsOUName = "Groups",

    [Parameter(Mandatory = $false)]
    [string]$DefaultPassword = "ChangeMe2026!"
)

# ============================================================
# INITIALIZATION
# ============================================================

$ErrorActionPreference = "Stop"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "[FATAL] Active Directory module could not be loaded." -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit 1
}

# ============================================================
# DOMAIN DETECTION
# ============================================================

try {
    $DomainInfo = Get-ADDomain -ErrorAction Stop
    $DomainDN   = $DomainInfo.DistinguishedName
    $DomainName = $DomainInfo.DNSRoot
}
catch {
    Write-Host "[FATAL] Active Directory domain could not be detected." -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit 1
}

Write-Host ""
Write-Host "=========================================="
Write-Host " ACTIVE DIRECTORY USER IMPORTER"
Write-Host "=========================================="
Write-Host ""
Write-Host "Domain: $DomainName"
Write-Host "DN:     $DomainDN"
Write-Host ""

$UsersOU  = "OU=$UsersOUName,$DomainDN"
$GroupsOU = "OU=$GroupsOUName,$DomainDN"

$Password = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force

# ============================================================
# COUNTERS
# ============================================================

$CreatedUsers  = 0
$UpdatedUsers  = 0
$CreatedGroups = 0
$CreatedOUs    = 0
$Errors        = 0

# ============================================================
# FUNCTION: ESCAPE LDAP FILTER VALUE
# ============================================================

function Escape-ADFilterValue {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    return $Value.Replace("'", "''")
}

# ============================================================
# FUNCTION: CONVERT TEXT TO SAFE USERNAME
# ============================================================

function Convert-ToUsername {
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    $Text = $Text.ToLowerInvariant()

    # Special characters replacement
    $Text = $Text.Replace(([string][char]0x00E6), "ae")
    $Text = $Text.Replace(([string][char]0x00F8), "o")
    $Text = $Text.Replace(([string][char]0x00DF), "ss")
    $Text = $Text.Replace(([string][char]0x0142), "l")

    # Normalize diacritics (ä->a, ö->o, ü->u, õ->o, etc.)
    $Normalized = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $Builder = New-Object System.Text.StringBuilder

    foreach ($Character in $Normalized.ToCharArray()) {
        $Category = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($Character)
        if ($Category -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$Builder.Append($Character)
        }
    }

    $Text = $Builder.ToString()

    # Formatting cleanups
    $Text = $Text -replace '\s+', '.'
    $Text = $Text -replace '[^a-z0-9._-]', ''
    $Text = $Text -replace '\.+', '.'
    $Text = $Text.Trim('.')

    return $Text
}

# ============================================================
# FUNCTION: CREATE OU IF NEEDED
# ============================================================

function Ensure-OU {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $SafeName = Escape-ADFilterValue $Name

    $ExistingOU = Get-ADOrganizationalUnit `
        -Filter "Name -eq '$SafeName'" `
        -SearchBase $Path `
        -SearchScope OneLevel `
        -ErrorAction SilentlyContinue

    if ($ExistingOU) {
        Write-Host "[EXISTS OU]  $Name"
        return $ExistingOU
    }

    try {
        $NewOU = New-ADOrganizationalUnit `
            -Name $Name `
            -Path $Path `
            -ProtectedFromAccidentalDeletion $false `
            -PassThru `
            -ErrorAction Stop

        $script:CreatedOUs++
        Write-Host "[CREATED OU] $Name" -ForegroundColor Green
        return $NewOU
    }
    catch {
        $script:Errors++
        Write-Host "[ERROR OU] $Name : $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# ============================================================
# FUNCTION: SELECT DEPARTMENT OU
# ============================================================

function Get-DepartmentOU {
    param(
        [Parameter(Mandatory)]
        [string]$Job
    )

    switch -Regex ($Job) {
        '^(CEO|COO|CTO)$'                                      { return "Management" }
        '(?i)Project Manager|Product Manager|Manager'          { return "Management" }
        '(?i)Sales'                                           { return "Sales" }
        '(?i)Marketing|Graphic|Event'                         { return "Marketing" }
        '(?i)HR|Social Worker'                                { return "HR" }
        '(?i)Financial|Accountant|Business Analyst'           { return "Finance" }
        '(?i)Mechanical Engineer|Architect|Research Scientist' { return "Engineering" }
        '(?i)IT|Software|Web|Database|Data Analyst|Developer'  { return "IT" }
        default                                               { return "Other" }
    }
}

# ============================================================
# FUNCTION: CREATE GROUP SAMACCOUNTNAME
# ============================================================

function Get-GroupSamAccountName {
    param(
        [Parameter(Mandatory)]
        [string]$Job
    )

    $SafeJob = $Job -replace '[^A-Za-z0-9]', '_'
    $SafeJob = $SafeJob -replace '_+', '_'
    $SafeJob = $SafeJob.Trim('_')

    if ([string]::IsNullOrWhiteSpace($SafeJob)) {
        $SafeJob = "Group"
    }

    # Short deterministic hash
    $SHA1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $Bytes     = [System.Text.Encoding]::UTF8.GetBytes($Job)
        $HashBytes = $SHA1.ComputeHash($Bytes)
        $Hash      = [System.BitConverter]::ToString($HashBytes).Replace("-", "").Substring(0,4)
    }
    finally {
        $SHA1.Dispose()
    }

    $MaxJobLength = 11
    if ($SafeJob.Length -gt $MaxJobLength) {
        $SafeJob = $SafeJob.Substring(0, $MaxJobLength)
    }

    return "JOB_${SafeJob}_$Hash"
}

# ============================================================
# CHECK INPUT FILE
# ============================================================

if (-not (Test-Path -LiteralPath $CsvPath)) {
    Write-Host "[FATAL] Input file not found:" -ForegroundColor Red
    Write-Host $CsvPath
    exit 1
}

# ============================================================
# CREATE ROOT OUs
# ============================================================

Ensure-OU -Name $UsersOUName -Path $DomainDN | Out-Null
Ensure-OU -Name $GroupsOUName -Path $DomainDN | Out-Null

# ============================================================
# CREATE DEPARTMENT OUs
# ============================================================

$DepartmentOUs = @(
    "Management",
    "IT",
    "Sales",
    "Marketing",
    "HR",
    "Finance",
    "Engineering",
    "Other"
)

foreach ($OUName in $DepartmentOUs) {
    Ensure-OU -Name $OUName -Path $UsersOU | Out-Null
}

# ============================================================
# READ INPUT FILE
# ============================================================

$Users = @()

foreach ($RawLine in Get-Content -LiteralPath $CsvPath -Encoding UTF8) {
    $Line = $RawLine.Trim()

    if ([string]::IsNullOrWhiteSpace($Line)) {
        continue
    }

    # Split Name from Location/Job
    if ($Line -notmatch '^(.*?)\s*-\s*(.*)$') {
        Write-Host "[INVALID LINE] $Line" -ForegroundColor Yellow
        $Errors++
        continue
    }

    $FullName = $Matches[1].Trim()
    $Rest     = $Matches[2].Trim()

    # Split Location and Job by last comma
    $LastComma = $Rest.LastIndexOf(',')
    if ($LastComma -lt 0) {
        Write-Host "[INVALID LINE] $Line" -ForegroundColor Yellow
        $Errors++
        continue
    }

    $Location = $Rest.Substring(0, $LastComma).Trim()
    $Job      = $Rest.Substring($LastComma + 1).Trim()

    if ([string]::IsNullOrWhiteSpace($Location) -or [string]::IsNullOrWhiteSpace($Job)) {
        Write-Host "[INVALID LINE] $Line" -ForegroundColor Yellow
        $Errors++
        continue
    }

    # Split First and Last name
    $NameParts = $FullName -split '\s+'
    if ($NameParts.Count -lt 2) {
        Write-Host "[INVALID NAME] $FullName" -ForegroundColor Yellow
        $Errors++
        continue
    }

    $FirstName = $NameParts[0]
    $LastName  = ($NameParts[1..($NameParts.Count - 1)] -join " ")

    $Users += [PSCustomObject]@{
        FirstName = $FirstName
        LastName  = $LastName
        FullName  = $FullName
        Location  = $Location
        Job       = $Job
    }
}

Write-Host ""
Write-Host "Loaded users: $($Users.Count)"
Write-Host ""

if ($Users.Count -eq 0) {
    Write-Host "[FATAL] No valid users found." -ForegroundColor Red
    exit 1
}

# ============================================================
# CREATE JOB GROUPS
# ============================================================

$Jobs = $Users.Job | Sort-Object -Unique

foreach ($Job in $Jobs) {
    $GroupName     = "JOB_$Job"
    $SafeGroupName = Escape-ADFilterValue $GroupName

    $Group = Get-ADGroup `
        -Filter "Name -eq '$SafeGroupName'" `
        -SearchBase $GroupsOU `
        -SearchScope OneLevel `
        -ErrorAction SilentlyContinue

    if ($Group) {
        Write-Host "[EXISTS GROUP]  $GroupName"
        continue
    }

    $GroupSAM = Get-GroupSamAccountName -Job $Job
    $SafeSAM  = Escape-ADFilterValue $GroupSAM

    $SAMCollision = Get-ADGroup `
        -Filter "SamAccountName -eq '$SafeSAM'" `
        -ErrorAction SilentlyContinue

    if ($SAMCollision) {
        $RandomSuffix = Get-Random -Minimum 1000 -Maximum 9999
        $BaseSAM      = $GroupSAM

        if ($BaseSAM.Length -gt 15) {
            $BaseSAM = $BaseSAM.Substring(0, 15)
        }
        $GroupSAM = "${BaseSAM}_$RandomSuffix"
    }

    try {
        $Group = New-ADGroup `
            -Name $GroupName `
            -SamAccountName $GroupSAM `
            -GroupScope Global `
            -GroupCategory Security `
            -Path $GroupsOU `
            -Description "Job group: $Job" `
            -PassThru `
            -ErrorAction Stop

        $CreatedGroups++
        Write-Host "[CREATED GROUP] $GroupName" -ForegroundColor Green
    }
    catch {
        $Errors++
        Write-Host "[ERROR GROUP] $GroupName : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================
# CREATE / UPDATE USERS
# ============================================================

foreach ($User in $Users) {
    try {
        # Username generation
        $BaseUsername = Convert-ToUsername "$($User.FirstName).$($User.LastName)"

        if ([string]::IsNullOrWhiteSpace($BaseUsername)) {
            throw "Could not generate username."
        }

        if ($BaseUsername.Length -gt 20) {
            $BaseUsername = $BaseUsername.Substring(0, 20)
        }

        $SafeBaseUsername = Escape-ADFilterValue $BaseUsername

        # Existing user check
        $ExistingUser = Get-ADUser `
            -Filter "SamAccountName -eq '$SafeBaseUsername'" `
            -Properties Title, Office, DistinguishedName `
            -ErrorAction SilentlyContinue

        $Department = Get-DepartmentOU -Job $User.Job
        $OUPath     = "OU=$Department,$UsersOU"

        # Create new user
        if (-not $ExistingUser) {
            $Username = $BaseUsername
            $Counter  = 1

            while (Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue) {
                $Counter++
                $Suffix        = $Counter.ToString()
                $MaxBaseLength = 20 - $Suffix.Length
                $TempBase      = $BaseUsername

                if ($TempBase.Length -gt $MaxBaseLength) {
                    $TempBase = $TempBase.Substring(0, $MaxBaseLength)
                }
                $Username = "$TempBase$Suffix"
            }

            New-ADUser `
                -Name $User.FullName `
                -GivenName $User.FirstName `
                -Surname $User.LastName `
                -DisplayName $User.FullName `
                -SamAccountName $Username `
                -UserPrincipalName "$Username@$DomainName" `
                -Title $User.Job `
                -Office $User.Location `
                -Path $OUPath `
                -AccountPassword $Password `
                -Enabled $true `
                -ErrorAction Stop

            $ADUser = Get-ADUser -Identity $Username -Properties Title, Office
            $CreatedUsers++
            Write-Host "[CREATED USER] $($User.FullName) [$Username]" -ForegroundColor Green
        }
        # Update existing user
        else {
            $ADUser = $ExistingUser

            Set-ADUser `
                -Identity $ADUser.DistinguishedName `
                -Title $User.Job `
                -Office $User.Location `
                -ErrorAction Stop

            $UpdatedUsers++
            Write-Host "[UPDATED USER] $($User.FullName)"
        }

        # Assign to Job Group
        $GroupName     = "JOB_$($User.Job)"
        $SafeGroupName = Escape-ADFilterValue $GroupName

        $Group = Get-ADGroup `
            -Filter "Name -eq '$SafeGroupName'" `
            -SearchBase $GroupsOU `
            -SearchScope OneLevel `
            -ErrorAction SilentlyContinue

        if (-not $Group) {
            throw "Job group '$GroupName' was not found."
        }

        $AlreadyMember = Get-ADGroupMember -Identity $Group.DistinguishedName -ErrorAction Stop |
            Where-Object { $_.DistinguishedName -eq $ADUser.DistinguishedName }

        if (-not $AlreadyMember) {
            Add-ADGroupMember `
                -Identity $Group.DistinguishedName `
                -Members $ADUser.DistinguishedName `
                -ErrorAction Stop

            Write-Host "    -> Added to: $GroupName"
        }
        else {
            Write-Host "    -> Already in: $GroupName"
        }
    }
    catch {
        $Errors++
        Write-Host "[ERROR] $($User.FullName): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================
# FINAL REPORT
# ============================================================

Write-Host ""
Write-Host "=========================================="
Write-Host "              COMPLETED"
Write-Host "=========================================="
Write-Host ""
Write-Host "Domain:         $DomainName"
Write-Host "Loaded users:   $($Users.Count)"
Write-Host "Created users:  $CreatedUsers"
Write-Host "Updated users:  $UpdatedUsers"
Write-Host "Created groups: $CreatedGroups"
Write-Host "Created OUs:    $CreatedOUs"
Write-Host "Errors:         $Errors"
Write-Host ""

# ============================================================
# DISPLAY USERS
# ============================================================

Write-Host "=========================================="
Write-Host " USERS"
Write-Host "=========================================="
Write-Host ""

Get-ADUser -Filter * -SearchBase $UsersOU -Properties Title, Office |
    Select-Object Name, SamAccountName, Title, Office |
    Sort-Object Name |
    Format-Table -AutoSize

# ============================================================
# DISPLAY JOB GROUPS
# ============================================================

Write-Host ""
Write-Host "=========================================="
Write-Host " JOB GROUPS"
Write-Host "=========================================="
Write-Host ""

Get-ADGroup -Filter "Name -like 'JOB_*'" -SearchBase $GroupsOU -Properties Description |
    Sort-Object Name |
    ForEach-Object {
        $CurrentGroup = $_
        $Members = @(
            Get-ADGroupMember -Identity $CurrentGroup.DistinguishedName -ErrorAction SilentlyContinue
        )

        Write-Host "$($CurrentGroup.Name) [$($Members.Count) users]"
        foreach ($Member in $Members) {
            Write-Host "    $($Member.Name)"
        }
    }

Write-Host ""
Write-Host "=========================================="
if ($Errors -eq 0) {
    Write-Host " SUCCESS - NO ERRORS" -ForegroundColor Green
}
else {
    Write-Host " COMPLETED WITH $Errors ERROR(S)" -ForegroundColor Red
}
Write-Host "=========================================="
Write-Host ""
