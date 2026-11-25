# Writes the os-* script fixtures in this directory (#52): scripts signed by
# the OS's own signer (`Set-AuthenticodeSignature`), on Windows, with a
# throwaway self-signed code-signing certificate made here and deleted after.
# No private key is kept.
#
# They cover the case jsign and the OS disagree on: VBScript, JScript and
# Windows Script Files in UTF-8 with a byte order mark, in every line
# ending, with ASCII text and with text outside ASCII:
#
#   os-<format>-utf8bom-<text>-<eol>.<ext>
#     format: js, vbs, wsf
#     text:   ascii, unicode (one character outside the Basic Multilingual
#             Plane, so UTF-16 has a surrogate pair)
#     eol:    crlf, lf, cr (the script's own lines)
#
# The OS's verifier accepts the ascii ones (their root is in no store, so
# only trust fails) and reports a hash mismatch for the unicode ones, which
# its own signer made. tests/script.rs requires the same verdicts.
#
# Run from Windows PowerShell 5.1, with the output directory:
#   powershell.exe -NoProfile -File generate-os.ps1 <out-dir>
param([Parameter(Mandatory)] [string] $Out)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $Out | Out-Null
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Palisade OS Fixture Signer' `
  -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 2048 `
  -NotAfter (Get-Date).AddYears(20)
try {
  $words = @{
    ascii   = 'palisade os fixture'
    unicode = 'palisade os fixture caf' + [char]0xe9 + ' ' + [char]0x20ac + ' ' +
              [char]::ConvertFromUtf32(0x1F600)
  }
  foreach ($format in 'js', 'vbs', 'wsf') {
    foreach ($text in 'ascii', 'unicode') {
      foreach ($eol in 'crlf', 'lf', 'cr') {
        $w = $words[$text]
        $body = switch ($format) {
          'js'  { "// $w`nWScript.Echo(`"$w`");`n" }
          'vbs' { "' $w`nWScript.Echo `"$w`"`n" }
          'wsf' { "<job id=`"t`">`n<script language=`"VBScript`">`n' $w`nWScript.Echo `"$w`"`n</script>`n</job>`n" }
        }
        switch ($eol) {
          'crlf' { $body = $body -replace "`n", "`r`n" }
          'cr'   { $body = $body -replace "`n", "`r" }
        }
        $bytes = [byte[]](0xef, 0xbb, 0xbf) + [Text.UTF8Encoding]::new($false).GetBytes($body)
        $path = Join-Path $Out "os-$format-utf8bom-$text-$eol.$format"
        [IO.File]::WriteAllBytes($path, $bytes)
        $signed = Set-AuthenticodeSignature -LiteralPath $path -Certificate $cert -HashAlgorithm SHA256
        if ($null -eq $signed.SignerCertificate) { throw "$path was not signed: $($signed.StatusMessage)" }
      }
    }
  }
} finally {
  Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey
}
