rule TRELLIX_ARC_Mimikatz_Utility_Softcell : HACKTOOL FILE
{
	meta:
		description = "Rule to detect Mimikatz utility used in the SoftCell operation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "0c01a2f6-cf3c-57b3-8f19-94d320422658"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_Operation_SoftCell.yar#L211-L258"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "4ccb44bf0d490a18e35290d904326ce14cdc92c96be1a38e6059431645233e37"
		score = 75
		quality = 68
		tags = "HACKTOOL, FILE"
		rule_version = "v1"
		malware_type = "hacktool"
		malware_family = "Hacktool:W32/Mimikatz"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "livessp.dll" fullword wide
		$s2 = "\\system32\\tapi32.dll" fullword wide
		$s3 = " * Process Token : " fullword wide
		$s4 = "lsadump" fullword wide
		$s5 = "-nl - skip lsa dump..." fullword wide
		$s6 = "lsadump::sam" fullword wide
		$s7 = "lsadump::lsa" fullword wide
		$s8 = "* NL$IterCount %u, %u real iter(s)" fullword wide
		$s9 = "* Iter to def (%d)" fullword wide
		$s10 = " * Thread Token  : " fullword wide
		$s11 = " * RootKey  : " fullword wide
		$s12 = "lsadump::cache" fullword wide
		$s13 = "sekurlsa::logonpasswords" fullword wide
		$s14 = "(commandline) # %s" fullword wide
		$s15 = ">>> %s of '%s' module failed : %08x" fullword wide
		$s16 = "UndefinedLogonType" fullword wide
		$s17 = " * Username : %wZ" fullword wide
		$s18 = "logonPasswords" fullword wide
		$s19 = "privilege::debug" fullword wide
		$s20 = "token::elevate" fullword wide
		$op0 = { e8 0b f5 00 00 90 39 35 30 c7 02 00 75 34 48 8b }
		$op1 = { eb 34 48 8b 4d cf 48 8d 45 c7 45 33 c9 48 89 44 }
		$op2 = { 48 3b 0d 34 26 01 00 74 05 e8 a9 31 ff ff 48 8b }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( pe.imphash ( ) == "169e02f00c6fb64587297444b6c41ff4" and all of them )
}

rule TELEKOM_SECURITY_Get_Windows_Proxy_Configuration : CAPABILITY HACKTOOL
{
	meta:
		description = "Queries Windows Registry for proxy configuration"
		author = "Thomas Barabosch, Deutsche Telekom Security"
		id = "b67b0b70-a95f-5c65-a522-ef4f41e36159"
		date = "2022-01-14"
		modified = "2023-12-12"
		reference = "https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-ie-clientnetworkprotocolimplementation-hklmproxyserver"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/hacktools/hacktools.yar#L44-L57"
		license_url = "N/A"
		logic_hash = "db52782a56d42f6e460466ea46993490bbbceeb7422d45211f064edb2e37a8eb"
		score = 75
		quality = 70
		tags = "CAPABILITY, HACKTOOL"

	strings:
		$a = "Software\\Microsoft\\Windows\\Currentversion\\Internet Settings" ascii wide
		$b = "ProxyEnable" ascii wide
		$c = "ProxyServer" ascii wide

	condition:
		all of them
}

rule TELEKOM_SECURITY_Cn_Utf8_Windows_Terminal : CAPABILITY HACKTOOL
{
	meta:
		description = "This is a (dirty) hack to display UTF-8 on Windows command prompt."
		author = "Thomas Barabosch, Deutsche Telekom Security"
		id = "a1beee71-c526-58fb-a255-dba55ef7535b"
		date = "2022-01-14"
		modified = "2023-12-12"
		reference = "https://www.bitdefender.com/files/News/CaseStudies/study/401/Bitdefender-PR-Whitepaper-FIN8-creat5619-en-EN.pdf"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/hacktools/hacktools.yar#L59-L71"
		license_url = "N/A"
		logic_hash = "4c91280c3d6d3b48c4ee11bf3d0c2baecee1368fbf3951c0a3bf386454c557cf"
		score = 40
		quality = 20
		tags = "CAPABILITY, HACKTOOL"

	strings:
		$a = " chcp 65001 " ascii wide

	condition:
		$a
}

