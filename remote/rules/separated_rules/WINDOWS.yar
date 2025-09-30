rule SIGNATURE_BASE_SUSP_OBFUSC_Indiators_XML_Officedoc_Sep21_1 : WINDOWS CVE FILE
{
	meta:
		description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
		author = "Florian Roth (Nextron Systems)"
		id = "ffcaf270-f574-5692-90e5-6776c34eb71b"
		date = "2021-09-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cve_2021_40444.yar#L64-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "13de9f39b1ad232e704b5e0b5051800fcd844e9f661185ace8287a23e9b3868e"
		hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
		logic_hash = "fc8f0dd02460ab8f8cc6717c66eba51e6ed74881a48e92fd0bf978467dfb40e3"
		score = 65
		quality = 85
		tags = "WINDOWS, CVE, FILE"

	strings:
		$h1 = "<?xml " ascii wide
		$xml_e = "Target=\"&#" ascii wide
		$xml_mode_1 = "TargetMode=\"&#" ascii wide

	condition:
		filesize < 500KB and $h1 and 1 of ( $xml* )
}

rule SIGNATURE_BASE_SUSP_OBFUSC_Indiators_XML_Officedoc_Sep21_2 : WINDOWS CVE FILE
{
	meta:
		description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
		author = "Florian Roth (Nextron Systems)"
		id = "c3c5ec4f-5d2a-523c-bd4b-b75c04bac87d"
		date = "2021-09-18"
		modified = "2023-12-05"
		reference = "https://twitter.com/sudosev/status/1439205606129377282"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cve_2021_40444.yar#L83-L98"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "82c70e0f0b72a57302e5853cc53ae18dbb0bc8dabdfd27b473a7664b2fc5e874"
		score = 65
		quality = 85
		tags = "WINDOWS, CVE, FILE"

	strings:
		$h1 = "<?xml " ascii wide
		$a1 = "Target" ascii wide
		$a2 = "TargetMode" ascii wide
		$xml_e = "&#x0000" ascii wide

	condition:
		filesize < 500KB and all of them
}

rule SIGNATURE_BASE_MAL_BACKORDER_LOADER_WIN_Go_Jan23 : LOADER GOLANG BACKORDER MALWARE WINDOWS FILE
{
	meta:
		description = "Detects the BACKORDER loader compiled in GO which download and executes a second stage payload from a remote server."
		author = "Arda Buyukkaya (modified by Florian Roth)"
		id = "90a82f2c-be92-5d0b-b47e-f47db2b15867"
		date = "2025-01-23"
		modified = "2025-03-20"
		reference = "EclecticIQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/mal_win_go_backorder_loader.yar#L1-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "70c91ffdc866920a634b31bf4a070fb3c3f947fc9de22b783d6f47a097fec2d8"
		logic_hash = "9e79ec9e58e02b7660383ff20957b95bc3c61ed3badc9af3d5829ebe5bf6bd7b"
		score = 80
		quality = 85
		tags = "LOADER, GOLANG, BACKORDER, MALWARE, WINDOWS, FILE"

	strings:
		$GoBuildId = "Go build" ascii
		$x_DebugSymbol_1 = "C:/updatescheck/main.go"
		$x_DebugSymbol_2 = "C:/Users/IEUser/Desktop/Majestic/"
		$s_FunctionName_1 = "main.getUpdates.func"
		$s_FunctionName_2 = "main.obt_zip"
		$s_FunctionName_3 = "main.obtener_zip"
		$s_FunctionName_4 = "main.get_zip"
		$s_FunctionName_5 = "main.show_pr0gressbar"
		$s_FunctionName_6 = "main.pr0cess"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 10MB and $GoBuildId and ( 1 of ( $x* ) or 3 of them )
}

rule SIGNATURE_BASE_APT_Donotteam_Ytyframework : APT DONOTTEAM WINDOWS FILE
{
	meta:
		description = "Modular malware framework with similarities to EHDevel"
		author = "James E.C, ProofPoint"
		id = "6dd07019-aa5a-5966-8331-b6f6758b0652"
		date = "2018-08-03"
		modified = "2023-12-05"
		reference = "https://labs.bitdefender.com/2017/09/ehdevel-the-story-of-a-continuously-improving-advanced-threat-creation-toolkit/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_donotteam_ytyframework.yar#L3-L43"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "1e0c1b97925e1ed90562d2c68971e038d8506b354dd6c1d2bcc252d2a48bc31c"
		logic_hash = "8e2841fd4550f12d88fb451a893f1ba41f0d3c123d9c195fe97366202376ef61"
		score = 75
		quality = 83
		tags = "APT, DONOTTEAM, WINDOWS, FILE"

	strings:
		$x1 = "/football/download2/" ascii wide
		$x2 = "/football/download/" ascii wide
		$x3 = "Caption: Xp>" wide
		$x_c2 = "5.135.199.0" ascii fullword
		$a1 = "getGoogle" ascii fullword
		$a2 = "/q /noretstart" wide
		$a3 = "IsInSandbox" ascii fullword
		$a4 = "syssystemnew" ascii fullword
		$a5 = "ytyinfo" ascii fullword
		$a6 = "\\ytyboth\\yty " ascii
		$s1 = "SELECT Name FROM Win32_Processor" wide
		$s2 = "SELECT Caption FROM Win32_OperatingSystem" wide
		$s3 = "SELECT SerialNumber FROM Win32_DiskDrive" wide
		$s4 = "VM: Yes" wide fullword
		$s5 = "VM: No" wide fullword
		$s6 = "helpdll.dll" ascii fullword
		$s7 = "boothelp.exe" ascii fullword
		$s8 = "SbieDll.dll" wide fullword
		$s9 = "dbghelp.dll" wide fullword
		$s10 = "YesNoMaybe" ascii fullword
		$s11 = "saveData" ascii fullword
		$s12 = "saveLogs" ascii fullword

	condition:
		uint16be( 0 ) == 0x4d5a and filesize < 500KB and ( pe.imphash ( ) == "87775285899fa860b9963b11596a2ded" or 1 of ( $x* ) or 3 of ( $a* ) or 6 of ( $s* ) )
}

