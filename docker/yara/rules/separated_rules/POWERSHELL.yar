rule SECUINFRA_SUSP_Powershell_Download_Temp_Rundll : POWERSHELL DOWNLOAD FILE
{
	meta:
		description = "Detect a Download to %temp% and execution with rundll32.exe"
		author = "SECUINFRA Falcon Team"
		id = "6b09a6f0-29c6-5baf-ae64-7aa49a37a9d3"
		date = "2022-09-02"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/powershell.yar#L1-L17"
		license_url = "N/A"
		logic_hash = "4d7860dc94614b10bc0eea0189ad9b964399d4ee6404ebeaef40720c716c592d"
		score = 65
		quality = 70
		tags = "POWERSHELL, DOWNLOAD, FILE"

	strings:
		$location = "$Env:temp" nocase
		$download = "downloadfile(" nocase
		$rundll = "rundll32.exe"

	condition:
		filesize < 100KB and $location and $download and $rundll
}

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

rule SECUINFRA_SUSP_Powershell_Download_Temp_Rundll_1 : POWERSHELL DOWNLOAD
{
	meta:
		description = "Detect a Download to %temp% and execution with rundll32.exe"
		author = "SECUINFRA Falcon Team"
		id = "f7a9d2e6-bebf-598b-9e59-db0a3001b9f9"
		date = "2022-09-02"
		modified = "2022-02-19"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/PowerShell_Misc/download_variations.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "7982438c032127349fb1c3477a23bab1c92eb68d9c3b26e2f5fb0a8c332dbc44"
		score = 65
		quality = 70
		tags = "POWERSHELL, DOWNLOAD"

	strings:
		$location = "$Env:temp" nocase
		$download = "downloadfile(" nocase
		$rundll = "rundll32.exe"

	condition:
		$location and $download and $rundll
}

rule SIGNATURE_BASE_MAL_CRIME_Unknown_LNK_Jun21_1 : LNK POWERSHELL FILE
{
	meta:
		description = "Triggers on malicious link files which calls powershell with an obfuscated payload and downloads an HTA file."
		author = "Nils Kuhnert"
		id = "d1aac420-fd91-5577-8efd-fcdd7f733981"
		date = "2021-06-04"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/mal_crime_unknown.yar#L18-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "460e764cbd9fbfa1a2156059d0042a0bea5a939d501050a733a789d236015d37"
		score = 75
		quality = 85
		tags = "LNK, POWERSHELL, FILE"
		hash1 = "8fc7f25da954adcb8f91d5b0e1967e4a90ca132b280aa6ae73e150b55d301942"
		hash2 = "f5da192f4e4dfb6b728aee1821d10bec6d68fb21266ce32b688e8cae7898a522"
		hash3 = "183a9b3c04d16a1822c788d7a6e78943790ee2cdeea12a38e540281091316e45"
		hash4 = "a38c6aa3e1c429a27226519b38f39f03b0b1b9d75fd43cd7e067c5e542967afe"
		hash5 = "455f7b6b975fb8f7afc6295ec40dae5696f5063d1651f3b2477f10976a3b67b2"

	strings:
		$uid = "S-1-5-21-1437133880-1006698037-385855442-1004" wide

	condition:
		uint16( 0 ) == 0x004c and all of them
}

rule SIGNATURE_BASE_MAL_CRIME_Unknown_ISO_Jun21_1 : ISO POWERSHELL LNK FILE
{
	meta:
		description = "Triggers on ISO files that mimick NOBELIUM TTPs, but uses LNK files that call powershell instead."
		author = "Nils Kuhnert"
		id = "73a1fc44-45c4-5253-b81d-fa6686dc0644"
		date = "2021-06-04"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/mal_crime_unknown.yar#L35-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "49b61f498d3f4ee249d9687277e581a39e08ebb4e1a293170058fb5f770bde1f"
		score = 75
		quality = 85
		tags = "ISO, POWERSHELL, LNK, FILE"
		hash1 = "425dbed047dd2ce760d0848ebf7ad04b1ca360f111d557fc7bf657ae89f86d36"
		hash2 = "f6944b6bca627e219d9c5065f214f95eb2226897a3b823b645d0fd78c281b149"
		hash3 = "14d70a8bdd64e9a936c2dc9caa6d4506794505e0e3870e3a25d9d59bcafb046e"
		hash4 = "9b2ca8eb6db34b07647a74171a5ff4c0a2ca8000da9876ed2db6361958c5c080"

	strings:
		$uid = "S-1-5-21-1437133880-1006698037-385855442-1004" wide
		$magic = "CD001" ascii

	condition:
		filesize < 5MB and all of them
}

