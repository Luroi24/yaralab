rule SIGNATURE_BASE_SUSP_MAL_Signingcert_Feb24_1 : CVE_2024_1708 CVE_2024_1709 FILE
{
	meta:
		description = "Detects PE files signed with a certificate used to sign malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		id = "f25ea77a-1b4e-5c13-9117-eedf0c20335a"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L166-L184"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "824efe1fa441322d891805df9a1637ebb44d18889572604acc125bf79a2d1083"
		score = 75
		quality = 85
		tags = "CVE-2024-1708, CVE-2024-1709, FILE"
		hash1 = "37a39fc1feb4b14354c4d4b279ba77ba51e0d413f88e6ab991aad5dd6a9c231b"
		hash2 = "e8c48250cf7293c95d9af1fb830bb8a5aaf9cfb192d8697d2da729867935c793"

	strings:
		$s1 = "Wisdom Promise Security Technology Co." ascii
		$s2 = "Globalsign TSA for CodeSign1" ascii
		$s3 = { 5D AC 0B 6C 02 5A 4B 21 89 4B A3 C2 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 70000KB and all of them
}

rule SIGNATURE_BASE_MAL_CS_Loader_Feb24_1 : CVE_2024_1708 CVE_2024_1709 FILE
{
	meta:
		description = "Detects Cobalt Strike malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		id = "6c9914a4-b079-5a39-9d3b-7b9a2b54dc2b"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L186-L206"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "ae0e25c2dda1b727978977c674e834cd659661c597d88395a6f46ad5a179e9f0"
		score = 75
		quality = 85
		tags = "CVE-2024-1708, CVE-2024-1709, FILE"
		hash1 = "0a492d89ea2c05b1724a58dd05b7c4751e1ffdd2eab3a2f6a7ebe65bf3fdd6fe"

	strings:
		$s1 = "Dll_x86.dll" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and ( pe.exports ( "UpdateSystem" ) and ( pe.imphash ( ) == "0dc05c4c21a86d29f1c3bf9cc5b712e0" or $s1 ) )
}

rule SIGNATURE_BASE_MAL_RANSOM_Lockbit_Indicators_Feb24 : CVE_2024_1708 CVE_2024_1709 FILE
{
	meta:
		description = "Detects Lockbit ransomware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		id = "108430c8-4fe5-58a1-b709-539b257c120c"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L208-L228"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "e4cd6b1a1bc57bf25c71f6bc228f45e4a996f9d9d391aeb3dda9c7d7857610bc"
		score = 75
		quality = 85
		tags = "CVE-2024-1708, CVE-2024-1709, FILE"
		hash1 = "a50d9954c0a50e5804065a8165b18571048160200249766bfa2f75d03c8cb6d0"

	strings:
		$op1 = { 76 c1 95 8b 18 00 93 56 bf 2b 88 71 4c 34 af b1 a5 e9 77 46 c3 13 }
		$op2 = { e0 02 10 f7 ac 75 0e 18 1b c2 c1 98 ac 46 }
		$op3 = { 8b c6 ab 53 ff 15 e4 57 42 00 ff 45 fc eb 92 ff 75 f8 ff 15 f4 57 42 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( pe.imphash ( ) == "914685b69f2ac2ff61b6b0f1883a054d" or 2 of them ) or all of them
}

rule SIGNATURE_BASE_MAL_MSI_Mpyutils_Feb24_1 : CVE_2024_1708 CVE_2024_1709 FILE
{
	meta:
		description = "Detects malicious MSI package mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
		author = "Florian Roth"
		id = "e7794336-a325-5b92-8c25-81ed9cb28044"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L230-L247"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "ba20db486e5d3c29c9702e10628fb3c0e55e52bbec74e3a86ed6511a6475b82f"
		score = 70
		quality = 85
		tags = "CVE-2024-1708, CVE-2024-1709, FILE"
		hash1 = "8e51de4774d27ad31a83d5df060ba008148665ab9caf6bc889a5e3fba4d7e600"

	strings:
		$s1 = "crypt64ult.exe" ascii fullword
		$s2 = "EXPAND.EXE" wide fullword
		$s6 = "ICACLS.EXE" wide fullword

	condition:
		uint16( 0 ) == 0xcfd0 and filesize < 20000KB and all of them
}

rule SIGNATURE_BASE_MAL_Beacon_Unknown_Feb24_1 : CVE_2024_1708 CVE_2024_1709 FILE
{
	meta:
		description = "Detects malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709 "
		author = "Florian Roth"
		id = "9299fd44-5327-5a73-8299-108b710cb16e"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L249-L268"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "fd6ebc6676d677d6bc19398026eee7b7d2f9727ba7a3c79d1e970a6dc19548aa"
		score = 75
		quality = 85
		tags = "CVE-2024-1708, CVE-2024-1709, FILE"
		hash1 = "6e8f83c88a66116e1a7eb10549542890d1910aee0000e3e70f6307aae21f9090"
		hash2 = "b0adf3d58fa354dbaac6a2047b6e30bc07a5460f71db5f5975ba7b96de986243"
		hash3 = "c0f7970bed203a5f8b2eca8929b4e80ba5c3276206da38c4e0a4445f648f3cec"

	strings:
		$s1 = "Driver.dll" wide fullword
		$s2 = "X l.dlT" ascii fullword
		$s3 = "$928c7481-dd27-8e23-f829-4819aefc728c" ascii fullword

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 3 of ( $s* )
}

