# interactive_signins.ps1 - Fetch and display sign-in logs, detect MFA policy within log and highlights OAuth non-MFA signins

# Load Configuration
$configFilePath = ".\config\config.json"
if (-not (Test-Path $configFilePath)) {
    Write-Host "Error: Config file not found! Expected at $configFilePath" -ForegroundColor Red
    exit
}
$config = Get-Content -Raw -Path $configFilePath | ConvertFrom-Json
$tenantId = $config.tenantId
$clientId = $config.clientId
$clientSecret = $config.clientSecret

# Validate Configuration
if (-not $tenantId -or -not $clientId -or -not $clientSecret) {
    Write-Host "Error: Missing values in config.json. Please check the file." -ForegroundColor Red
    exit
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

# Function to get sign-in logs with retry logic
function Get-SignInLogs {
    param ([string]$url)
    $maxRetries = 5
    $retryCount = 0
    $waitTime = 5

    do {
        try {
            Write-Host "Fetching logs from: $url"
            $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -TimeoutSec 120
            return $response
        }
        catch {
            Write-Host "Error retrieving sign-in logs: $_" -ForegroundColor Yellow
            $retryCount++
            Start-Sleep -Seconds $waitTime
            $waitTime *= 2  # Exponential backoff
        }
    } while ($retryCount -lt $maxRetries)

    Write-Host "Failed to retrieve sign-in logs after multiple attempts." -ForegroundColor Red
    return $null
}

# API Endpoint - Fetch ALL sign-ins (No date filter)
$signinLogsUrl = "https://graph.microsoft.com/beta/auditLogs/signIns"
$allSigninLogs = @()
$filteredLogs = @()

# Retrieve logs with pagination
do {
    $signinLogs = Get-SignInLogs -url $signinLogsUrl
    if ($signinLogs -eq $null) { break }

    $allSigninLogs += $signinLogs.value

    # Handle pagination
    if ($signinLogs.'@odata.nextLink') {
        Write-Host "Fetching next page..."
        $signinLogsUrl = $signinLogs.'@odata.nextLink'
    } else {
        $signinLogsUrl = $null
    }
} while ($signinLogsUrl -ne $null)

# Process logs and print relevant details
Write-Host "`nProcessed Sign-In Logs" -ForegroundColor Cyan
foreach ($log in $allSigninLogs) {
    $logId = if ($log.id) { $log.id } else { "Unknown" }
    $user = $log.userDisplayName
    $username = $log.userPrincipalName
    $signInTime = $log.createdDateTime
    $appUsed = $log.clientAppUsed
    $errorCode = if ($log.status.errorCode) { $log.status.errorCode } else { "None" }
    $authRequirement = if ($log.authenticationRequirement) { $log.authenticationRequirement } else { "Unknown" }
    $mfaEnforced = $false

    # Check for Conditional Access Policies and MFA enforcement
    if ($log.appliedConditionalAccessPolicies) {
        foreach ($policy in $log.appliedConditionalAccessPolicies) {
            if ($policy.enforcedGrantControls -contains "Mfa") {
                $mfaEnforced = $true
            }
        }
    }

    # Determine MFA enforcement text
    $mfaText = if ($mfaEnforced) { "Yes" } else { "No" }

    # Highlight in red if single-factor auth and MFA enforced
    if ($authRequirement -eq "singleFactorAuthentication" -and $mfaEnforced) {
        Write-Host "Log ID: $logId | User: $user | Username: $username | App: $appUsed | Time: $signInTime | Error Code: $errorCode | Auth Requirement: $authRequirement | MFA Enforced: $mfaText" -ForegroundColor Red
        $filteredLogs += $log
    }
}

# Save filtered logs to JSON file
if ($filteredLogs.Count -gt 0) {
    $logFilePath = ".\output\signin_logs.json"
    $filteredLogs | ConvertTo-Json -Depth 10 | Out-File $logFilePath
    Write-Host "Suspicous sign-in log entries saved to: $logFilePath" -ForegroundColor Green
} else {
    Write-Host "No filtered sign-in logs to save." -ForegroundColor Yellow
}

Write-Host "`nProcessing complete!"
