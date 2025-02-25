# analyze_useragents.ps1 - Detect suspicious user-agents in sign-in logs

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

# Load Suspicious User-Agents List
$userAgentsFilePath = ".\config\suspicious_user_agents.json"
if (-not (Test-Path $userAgentsFilePath)) {
    Write-Host "Error: Suspicious user-agents JSON file not found! Expected at $userAgentsFilePath" -ForegroundColor Red
    exit
}
$userAgentsList = Get-Content -Raw -Path $userAgentsFilePath | ConvertFrom-Json
$suspiciousUserAgents = $userAgentsList.suspiciousAgents

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

    $maxRetries = 3
    $retryCount = 0
    do {
        try {
            $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers
            return $response
        }
        catch {
            Write-Host "Error retrieving sign-in logs. Retrying... ($retryCount of $maxRetries)" -ForegroundColor Yellow
            Start-Sleep -Seconds 5
            $retryCount++
        }
    } while ($retryCount -lt $maxRetries)

    Write-Host "Failed to retrieve sign-in logs after multiple attempts." -ForegroundColor Red
    return $null
}

# Get logs only from the past 7 days to prevent overload
$startDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
$signinLogsUrl = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $startDate&`$top=50"

$allSigninLogs = @()
$suspiciousSignins = @()

do {
    $signinLogs = Get-SignInLogs -url $signinLogsUrl
    if ($signinLogs -eq $null) { break }

    $allSigninLogs += $signinLogs.value

    # Check for next page of results
    $signinLogsUrl = $signinLogs.'@odata.nextLink'
} while ($signinLogsUrl -ne $null)

Write-Host "Total sign-ins retrieved: $($allSigninLogs.Count)"

# Print all user-agent strings found and check against suspicious list
Write-Host "`nChecking User-Agents for Suspicious Sign-Ins" -ForegroundColor Cyan
foreach ($log in $allSigninLogs) {
    $userAgent = $log.clientAppUsed
    Write-Host "  User: $($log.userDisplayName) | User-Agent: " $userAgent

    # Check if user-agent matches any in the suspicious list (case-insensitive)
    $matchedAgent = $suspiciousUserAgents | Where-Object { $userAgent -match [regex]::Escape($_) }

    if ($matchedAgent) {
        Write-Host "Suspicious Sign-In Detected: $($log.userDisplayName) using [$userAgent]" -ForegroundColor Red

        # Save details of suspicious sign-in
        $suspiciousSignins += @{
            "UserDisplayName" = $log.userDisplayName
            "UserPrincipalName" = $log.userPrincipalName
            "IPAddress" = $log.ipAddress
            "Location" = $log.location.city
            "SignInStatus" = $log.status.errorCode
            "RiskLevel" = $log.riskLevelAggregated
            "UserAgent" = $userAgent
            "MatchedAgent" = $matchedAgent
            "Time" = $log.createdDateTime
        }
    }
}

# Save suspicious results
$suspiciousSigninsFile = ".\output\suspicious_useragents.json"
if ($suspiciousSignins.Count -gt 0) {
    $suspiciousSignins | ConvertTo-Json -Depth 10 | Set-Content -Path $suspiciousSigninsFile
    Write-Host "Suspicious sign-ins saved to: $suspiciousSigninsFile" -ForegroundColor Green
} else {
    Write-Host "No suspicious user-agents used in sign-ins detected." -ForegroundColor Yellow
}
