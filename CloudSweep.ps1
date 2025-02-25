# CloudSweep main

Write-Host @"
CloudSweep
    - EntraID Analysis by CyberMaxx Security Research Team
"@

Write-Host "`nLoading Configuration Data..."
$configFilePath = ".\config\config.json"
if (-not (Test-Path $configFilePath)) {
    Write-Host "Error: Config file not found! Expected at $configFilePath" -ForegroundColor Red
    exit
}
Write-Host "  Complete!" -ForegroundColor Green

$config = Get-Content -Raw -Path $configFilePath | ConvertFrom-Json
$tenantId = $config.tenantId
$clientId = $config.clientId
$clientSecret = $config.clientSecret

# Validate input
if (-not $tenantId -or -not $clientId -or -not $clientSecret) {
    Write-Host "Error: Missing values in config.json. Please check the file." -ForegroundColor Red
    exit
}

# Load Permissions Mapping
$permissionsFilePath = ".\config\permissions.json"
if (-not (Test-Path $permissionsFilePath)) {
    Write-Host "Error: Permissions JSON file not found! Expected at $permissionsFilePath" -ForegroundColor Red
    exit
}
$permissionsDict = Get-Content -Raw -Path $permissionsFilePath | ConvertFrom-Json

# Load Known Malicious Apps List
$appListFilePath = ".\config\malicious_app_list.json"
if (-not (Test-Path $appListFilePath)) {
    Write-Host "Error: Malicious app list not found! Expected at $appListFilePath" -ForegroundColor Red
    exit
}
$appList = Get-Content -Raw -Path $appListFilePath | ConvertFrom-Json

# Load Application Whitelist (App ID as Key)
$whitelistFilePath = ".\config\whitelist.json"
if (Test-Path $whitelistFilePath) {
    $whitelist = Get-Content -Raw -Path $whitelistFilePath | ConvertFrom-Json
} else {
    Write-Host "Whitelist not found. Creating an empty whitelist." -ForegroundColor Yellow
    $whitelist = @{}
}

# Load or Create OAuth App Names List
$oauthAppNamesFilePath = ".\output\oauth_app_review.json"
if (Test-Path ($oauthAppNamesFilePath)) {
    $oauthAppNames = Get-Content -Raw -Path $oauthAppNamesFilePath | ConvertFrom-Json
} else {
    Write-Host "Creating new OAuth application names list." -ForegroundColor Yellow
    $oauthAppNames = @()
}

# OAuth2 Token URL
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Prepare authentication request
$body = @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

# Request Access Token
$response = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body
$accessToken = $response.access_token

# Define headers for API calls
$headers = @{ Authorization = "Bearer $accessToken"; Accept = "application/json" }

# Fetch OAuth2 applications
$appsUrl = "https://graph.microsoft.com/v1.0/applications"
$apps = Invoke-RestMethod -Method Get -Uri $appsUrl -Headers $headers

# Function to map permission IDs to display names
function Get-PermissionDetails($permissionId) {
    foreach ($perm in $permissionsDict.delegatedPermissions) {
        if ($perm.id -eq $permissionId) { return "$($perm.displayName) | Type: Delegated" }
    }
    foreach ($perm in $permissionsDict.applicationPermissions) {
        if ($perm.id -eq $permissionId) { return "$($perm.displayName) | Type: Application" }
    }
    return "UNKNOWN ($permissionId)"
}

# Process OAuth applications
if ($apps.value.Count -gt 0) {
    Write-Host "`nOAuth Applications Found In Entra ID Tenant ($tenantId):" -ForegroundColor Cyan
    foreach ($app in $apps.value) {
        if ($whitelist.PSObject.Properties.Name -contains $app.appId) {
            continue
        }

        Write-Host "-----------------------------"
        Write-Host "Display Name: $($app.displayName)"
        Write-Host "App ID: $($app.appId)"
        Write-Host "Object ID: $($app.id)"

        if ($appList.PSObject.Properties.Name -contains $app.appId) {
            $status = "Known Malicious"
            Write-Host "WARNING: Known Malicious App" -ForegroundColor Red
        } else {
            $status = "Unknown"
            Write-Host "Unknown Application. Further review required." -ForegroundColor Yellow
        }

        # Check for suspicious names
        $regexPattern = '^[^a-zA-Z0-9]+$'
        $suspiciousName = $app.displayName -match $regexPattern -or $app.displayName -match "(?i)test"

        if ($suspiciousName) {
            Write-Host "Suspicious Name: $suspiciousName" -ForegroundColor Red
        }
        else {Write-Host "Suspicious Name: False"}

        # Retrieve permissions
        $appPermissions = @()
        if ($app.requiredResourceAccess -and $app.requiredResourceAccess.Count -gt 0) {
            foreach ($resourceAccess in $app.requiredResourceAccess) {
                foreach ($permission in $resourceAccess.resourceAccess) {
                    $appPermissions += Get-PermissionDetails -permissionId $permission.id
                }
            }
        }

        Write-Host "Permissions:"
        foreach ($perm in $appPermissions) {
            Write-Host "  - $perm"
        }

        # Find existing entry and update or add new entry
        $existingApp = $oauthAppNames | Where-Object { $_.AppId -eq $app.appId }

        if ($existingApp) {
            $existingApp | Add-Member -MemberType NoteProperty -Name "Status" -Value $status -Force
            $existingApp | Add-Member -MemberType NoteProperty -Name "Permissions" -Value $appPermissions -Force
            $existingApp | Add-Member -MemberType NoteProperty -Name "SuspiciousName" -Value $suspiciousName -Force
        } else {
            $oauthAppNames += [PSCustomObject]@{
                DisplayName    = $app.displayName
                Status         = $status
                AppId          = $app.appId
                ObjectId       = $app.id
                RegisteredOn   = $app.createdDateTime
                Permissions    = $appPermissions
                SuspiciousName = $suspiciousName
            }
        }
    }

    # Save updated OAuth app names list
    $oauthAppNames | ConvertTo-Json -Depth 10 | Set-Content -Path $oauthAppNamesFilePath
    Write-Host "Updated OAuth app names list: $oauthAppNamesFilePath" -ForegroundColor Green
}

Write-Host "`nStarting Recent User-Agent Analysis..." -ForegroundColor Cyan
& ".\analyze_useragents.ps1"

Write-Host "`nComparing OAuth2 Application Names With Users & Service Principals..." -ForegroundColor Cyan
& ".\match_username_oauth.ps1"

# Checking for SFA used with MFA accounts:
& ".\review_oauth_signin_mfa.ps1"

Write-Host "`nAnalysis Completed. Results stored in /output" -ForegroundColor Cyan
