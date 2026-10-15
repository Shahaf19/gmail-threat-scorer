# Deploys the backend to Cloud Run and proves it is not publicly callable.
# Caller authentication is enforced by Cloud Run (Google verifies the add-on's identity token),
# not by the Python code, so every deploy must go through this script to keep that guarantee.
$ErrorActionPreference = 'Stop'

$Project = 'gmail-threat-scorer'
$Region = 'europe-west1'
$Service = 'gmail-threat-scorer'
$BuildServiceAccount = "projects/$Project/serviceAccounts/cloud-run-builder@$Project.iam.gserviceaccount.com"
$MaxInstances = 2
$Memory = '512Mi'
$PublicMembers = @('allUsers', 'allAuthenticatedUsers')
$ExpectedAnonymousStatus = '403'

gcloud run deploy $Service --source $PSScriptRoot --project $Project --region $Region `
    --no-allow-unauthenticated --max-instances $MaxInstances --memory $Memory `
    --build-service-account $BuildServiceAccount --quiet
if ($LASTEXITCODE -ne 0) { throw 'Deploy failed.' }

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
