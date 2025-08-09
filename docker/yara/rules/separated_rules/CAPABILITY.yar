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

