# Deploys the backend to Cloud Run and proves it is not publicly callable.
# Caller authentication is enforced by Cloud Run (Google verifies the add-on's identity token),
# not by the Python code, so every deploy must go through this script to keep that guarantee.
param(
    # The Google account that uses the add-on: the only caller allowed in. Defaults to the deploying account.
    [string]$InvokerEmail = (gcloud config get-value account)
)
$ErrorActionPreference = 'Stop'

$Project = 'gmail-threat-scorer'
$Region = 'europe-west1'
$Service = 'gmail-threat-scorer'
$BuildServiceAccount = "projects/$Project/serviceAccounts/cloud-run-builder@$Project.iam.gserviceaccount.com"
$MaxInstances = 2
$Memory = '512Mi'
$PublicMembers = @('allUsers', 'allAuthenticatedUsers')
$ExpectedAnonymousStatus = '403'
# The abuse.ch key lives in Secret Manager; Cloud Run hands it to the app as an environment variable.
$SecretName = 'abusech-auth-key'
$SecretVariable = 'ABUSECH_AUTH_KEY'

$secretArguments = @()
if (gcloud secrets list --project $Project --filter="name:$SecretName" --format='value(name)') {
    # The service runs as the project's default compute account; it may read this one secret and nothing else.
    $projectNumber = gcloud projects describe $Project --format='value(projectNumber)'
    gcloud secrets add-iam-policy-binding $SecretName --project $Project `
        --member="serviceAccount:$projectNumber-compute@developer.gserviceaccount.com" `
        --role='roles/secretmanager.secretAccessor' --quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Granting secret access failed.' }
    $secretArguments = @('--set-secrets', "$SecretVariable=${SecretName}:latest")
} else {
    Write-Warning "Secret '$SecretName' not found: known-threat lookups will be disabled."
}

gcloud run deploy $Service --source $PSScriptRoot --project $Project --region $Region `
    --no-allow-unauthenticated --max-instances $MaxInstances --memory $Memory `
    --build-service-account $BuildServiceAccount @secretArguments --quiet
if ($LASTEXITCODE -ne 0) { throw 'Deploy failed.' }

# Allow exactly one account to call the service. The custom audience only says which tokens are
# accepted; this binding says whose.
gcloud run services add-iam-policy-binding $Service --project $Project --region $Region `
    --member="user:$InvokerEmail" --role='roles/run.invoker' --quiet | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Granting invoker access failed.' }

# Check 1: no IAM binding opens the service to everyone.
$policy = gcloud run services get-iam-policy $Service --project $Project --region $Region --format=json | Out-String
foreach ($member in $PublicMembers) {
    if ($policy -match "`"$member`"") { throw "SERVICE IS PUBLIC: '$member' can invoke it. Remove that binding now." }
}

# Check 2: an anonymous request is actually rejected at the door.
$url = gcloud run services describe $Service --project $Project --region $Region --format='value(status.url)'
$status = curl.exe -s -o NUL -w '%{http_code}' "$url/health"
if ($status -ne $ExpectedAnonymousStatus) {
    throw "SERVICE MAY BE PUBLIC: anonymous request got HTTP $status, expected $ExpectedAnonymousStatus."
}

Write-Host "Deployed $url - anonymous requests are rejected (HTTP $status)."
