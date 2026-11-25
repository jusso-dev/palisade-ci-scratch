# Signs a matrix of probe scripts with a throwaway self-signed certificate,
# using the OS's own signer, and prints each verdict and file as base64.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:RUNNER_TEMP 'probe'
New-Item -ItemType Directory -Force $dir | Out-Null
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Scratch Probe' `
  -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 2048
$uni = 'probe caf' + [char]0xe9 + ' ' + [char]0x20ac + ' ' + [char]::ConvertFromUtf32(0x1F600)
$asc = 'probe text'
function Body($fmt, $w) {
  switch ($fmt) {
    'ps1' { "# $w`nWrite-Output `"$w`"`n" }
    'vbs' { "' $w`nWScript.Echo `"$w`"`n" }
    'js'  { "// $w`nWScript.Echo(`"$w`");`n" }
    'wsf' { "<job id=`"t`">`n<script language=`"VBScript`">`n' $w`nWScript.Echo `"$w`"`n</script>`n</job>`n" }
  }
}
$cases = @()
foreach ($fmt in 'js','vbs','wsf','ps1') {
  foreach ($eol in 'crlf','lf','cr') {
    foreach ($enc in 'nobom','utf8bom','utf16le','utf16be') {
      foreach ($txt in 'ascii','unicode') {
        if ($enc -eq 'nobom' -and $txt -eq 'unicode') { continue }
        $cases += ,@($fmt, $eol, $enc, $txt)
      }
    }
  }
}
foreach ($c in $cases) {
  $fmt, $eol, $enc, $txt = $c
  $w = if ($txt -eq 'ascii') { $asc } else { $uni }
  $b = Body $fmt $w
  switch ($eol) { 'crlf' { $b = $b -replace "`n", "`r`n" } 'cr' { $b = $b -replace "`n", "`r" } }
  $bytes = switch ($enc) {
    'nobom'   { [Text.Encoding]::ASCII.GetBytes($b) }
    'utf8bom' { [byte[]](0xef,0xbb,0xbf) + [Text.UTF8Encoding]::new($false).GetBytes($b) }
    'utf16le' { [byte[]](0xff,0xfe) + [Text.Encoding]::Unicode.GetBytes($b) }
    'utf16be' { [byte[]](0xfe,0xff) + [Text.Encoding]::BigEndianUnicode.GetBytes($b) }
  }
  $name = "$fmt-$enc-$txt-$eol.$fmt"
  $path = Join-Path $dir $name
  [IO.File]::WriteAllBytes($path, $bytes)
  try {
    $s = Set-AuthenticodeSignature -LiteralPath $path -Certificate $cert -HashAlgorithm SHA256
    $g = Get-AuthenticodeSignature -LiteralPath $path
    $data = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))
    "PROBE|$name|$($s.Status)|$($g.Status)|$($g.StatusMessage -replace '\s+',' ')|$data"
  } catch {
    "PROBE|$name|ERROR|ERROR|$($_.Exception.Message -replace '\s+',' ')|"
  }
}
