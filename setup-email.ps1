# Saves the details used to send sign-in codes into .env.local (private to this computer, never committed).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Read-Secret($prompt) {
  $sec = Read-Host $prompt -AsSecureString
  $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
  return ($plain -replace '\s', '')
}

Write-Host ''
Write-Host 'How will sign-in codes be emailed?'
Write-Host '  1) EmailJS   (free: 200 emails a month; needs a service, a template and 2 keys)'
Write-Host '  2) Gmail     (free: about 500 a day; needs a Google App Password)'
$choice = (Read-Host 'Type 1 or 2').Trim()

$keep = @()
if (Test-Path .env.local) {
  $keep = @(Get-Content .env.local | Where-Object { $_ -notmatch '^(SMTP_|MAIL_FROM|EMAILJS_|OTP_DEV_CONSOLE)' })
}

if ($choice -eq '1') {
  Write-Host ''
  Write-Host 'In EmailJS: Account > Security > turn ON "allow API calls from non-browser applications".'
  $service = (Read-Host 'Service ID (starts with service_)').Trim()
  $template = (Read-Host 'Template ID (starts with template_)').Trim()
  $public = (Read-Host 'Public Key').Trim()
  $private = Read-Secret 'Private Key (typing is hidden)'
  if (-not $service -or -not $template -or -not $public) { Write-Host 'Missing a value. Nothing was saved.'; exit 1 }
  $lines = $keep + @("EMAILJS_SERVICE_ID=$service", "EMAILJS_TEMPLATE_ID=$template", "EMAILJS_PUBLIC_KEY=$public", "EMAILJS_PRIVATE_KEY=$private")
}
elseif ($choice -eq '2') {
  Write-Host ''
  Write-Host 'Turn on 2-Step Verification, then create an App Password at https://myaccount.google.com/apppasswords'
  $user = (Read-Host 'Gmail address that will send the codes').Trim()
  $pass = Read-Secret 'App Password (typing is hidden)'
  if ($user -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$' -or $pass.Length -lt 8) { Write-Host 'That does not look right. Nothing was saved.'; exit 1 }
  $lines = $keep + @('SMTP_HOST=smtp.gmail.com', 'SMTP_PORT=465', "SMTP_USER=$user", "SMTP_PASS=$pass", "MAIL_FROM=`"AI Digital Library`" <$user>")
}
else {
  Write-Host 'Please run again and type 1 or 2.'
  exit 1
}

$lines | Set-Content .env.local -Encoding ascii
Write-Host ''
Write-Host 'Saved. Now close the system window and start it again (start.bat).'
