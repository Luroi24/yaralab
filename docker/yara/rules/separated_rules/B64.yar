rule SECUINFRA_SUSP_Powershell_Base64_Decode : POWERSHELL B64 FILE
{
	meta:
		description = "Detects PowerShell code to decode Base64 data. This can yield many FP"
		author = "SECUINFRA Falcon Team"
		id = "7cb01c0b-d7e3-5196-b78d-f41765ba0368"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/powershell.yar#L19-L31"
		license_url = "N/A"
		logic_hash = "b323089ac61823d969d04a05890ad9fffe8589165d4b026b08e9fd633d4247de"
		score = 60
		quality = 50
		tags = "POWERSHELL, B64, FILE"

	strings:
		$b64_decode = "[System.Convert]::FromBase64String("

	condition:
		filesize < 500KB and $b64_decode
}

