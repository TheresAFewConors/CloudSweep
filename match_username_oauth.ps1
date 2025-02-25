# list_oauth_user_matches.ps1 - Checks if OAuth app names match user names (ignoring case, whitespace, and special characters)

param (
    [string]$configPath = ".\config\config.json",
    [string]$matchesPath = ".\output\oauth_user_matches.json"
)

# Load Configuration
if (-not (Test-Path $configPath)) {
    Write-Host "Error: Config file not found! Expected at $configPath" -ForegroundColor Red
    exit
}
$config = Get-Content -Raw -Path $configPath | ConvertFrom-Json
$tenantId = $config.tenantId
$clientId = $config.clientId
$clientSecret = $config.clientSecret

# Validate input
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

# Fetch all OAuth applications
$oauthAppsUrl = "https://graph.microsoft.com/v1.0/applications?`$top=999"
Write-Host "Fetching all registered OAuth applications..."
$oauthApps = Invoke-RestMethod -Method Get -Uri $oauthAppsUrl -Headers $headers

# Print all found OAuth applications
Write-Host "`nFound OAuth Applications"
if ($oauthApps.value.Count -gt 0) {
    #foreach ($app in $oauthApps.value) {
    #    Write-Host " $($app.displayName) (App ID: $($app.appId))"
   # }
    Write-Host "  Total OAuth Applications Found: $($oauthApps.value.Count)`n"
} else {
    Write-Host "No OAuth applications found!"
}

# Fetch all users
$usersUrl = "https://graph.microsoft.com/v1.0/users?`$top=999"
Write-Host "Fetching all users..."
$users = Invoke-RestMethod -Method Get -Uri $usersUrl -Headers $headers

# Print all found users
if ($users.value.Count -gt 0) {
  #  foreach ($user in $users.value) {
  #      Write-Host " $($user.displayName) (User Principal Name: $($user.userPrincipalName))"
  #  }
    Write-Host "  Total Users Found: $($users.value.Count)`n"
} else {
    Write-Host "No users found!"
}

# Normalize text (regex to remove whitespace, special characters, and convert to lowercase)
function Normalize-Name($name) {
    return ($name -replace '[\s._-]', '').ToLower()
}

# Check for matching names between OAuth apps and users
Write-Host "Checking for matches..."
$matchingEntries = @()
foreach ($app in $oauthApps.value) {
    $normalizedAppName = Normalize-Name $app.displayName

    foreach ($user in $users.value) {
        $normalizedUserName = Normalize-Name $user.displayName

        if ($normalizedAppName -eq $normalizedUserName) {
            Write-Host "  Match Found: OAuth App '$($app.displayName)' matches User '$($user.displayName)'" -ForegroundColor Red
            $matchingEntries += @{
                "DisplayName" = $app.displayName
                "AppId" = $app.appId
                "ObjectId" = $app.id
                "CreatedDateTime" = $app.createdDateTime
                "PublisherDomain" = $app.publisherDomain
                "SignInAudience" = $app.signInAudience
                "AppRoles" = $app.appRoles
                "RequiredResourceAccess" = $app.requiredResourceAccess
            }
        }
    }
}

# Save matches to file (if any exist)
if ($matchingEntries.Count -gt 0) {
    $matchingEntries | ConvertTo-Json -Depth 10 | Set-Content -Path $matchesPath
    Write-Host "`nMatching OAuth applications saved to: $matchesPath"
} else {
    Write-Host "`nNo matches found between OAuth apps and users."
}
