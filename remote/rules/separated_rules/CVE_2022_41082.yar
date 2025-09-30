rule SIGNATURE_BASE_EXPL_LOG_Proxynotshell_OWASSRF_Powershell_Proxy_Log_Dec22_1 : CVE_2022_41040 CVE_2022_41082
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		id = "a61f6582-474f-5b6f-b8f5-329c0bcc4017"
		date = "2022-12-22"
		modified = "2023-12-05"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_proxynotshell_owassrf_dec22.yar#L2-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "1e8f5a3440f8b4b1850fddbd19f63796ad0f28178c678e9f464b7e4ab5ca944f"
		score = 70
		quality = 85
		tags = "CVE-2022-41040, CVE-2022-41082"

	strings:
		$s1 = "/owa/mastermailbox%40outlook.com/powershell" ascii wide
		$sa1 = " 200 " ascii wide
		$sa2 = " POST " ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		all of ( $s* ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_EXPL_LOG_Proxynotshell_OWASSRF_Powershell_Proxy_Log_Dec22_2 : CVE_2022_41040 CVE_2022_41082
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		id = "85722997-fd28-51cf-817e-7a314e284b0b"
		date = "2022-12-22"
		modified = "2023-12-05"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_proxynotshell_owassrf_dec22.yar#L24-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "73ce86b7a673719c916666fa06963b774edad5b2cd804994614afd83ea75ecef"
		score = 60
		quality = 60
		tags = "CVE-2022-41040, CVE-2022-41082"

	strings:
		$sr1 = / \/owa\/[^\/\s]{1,30}(%40|@)[^\/\s\.]{1,30}\.[^\/\s]{2,3}\/powershell / ascii wide
		$sa1 = " 200 " ascii wide
		$sa2 = " POST " ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		all of ( $s* ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_EXPL_LOG_Proxynotshell_OWASSRF_Powershell_Proxy_Log_Dec22_3 : CVE_2022_41040 CVE_2022_41082
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		id = "76dd786e-daaa-5cd9-8e3e-50d9eab7f9d2"
		date = "2022-12-22"
		modified = "2023-12-05"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_proxynotshell_owassrf_dec22.yar#L47-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "607d3743a46e0c5000b9c7847dd89f5d7ccf29f4f1af9bce6870d7738f071f5c"
		score = 60
		quality = 85
		tags = "CVE-2022-41040, CVE-2022-41082"

	strings:
		$sa1 = " POST /powershell - 444 " ascii wide
		$sa2 = " POST /Powershell - 444 " ascii wide
		$sb1 = " - 200 0 0 2" ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		1 of ( $sa* ) and $sb1 and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_EXPL_LOG_Proxynotshell_Powershell_Proxy_Log_Dec22_1 : CVE_2022_41040 CVE_2022_41082
{
	meta:
		description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
		author = "Florian Roth (Nextron Systems)"
		id = "5af3ae70-8897-593f-a413-82ca1d1ba961"
		date = "2022-12-22"
		modified = "2023-01-26"
		reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_proxynotshell_owassrf_dec22.yar#L68-L86"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "f2aac61bc17f74901ec8d638d5cfaaa45bbd2a4e40e5d915bf2a946daed411d2"
		score = 70
		quality = 85
		tags = "CVE-2022-41040, CVE-2022-41082"

	strings:
		$re1 = /,\/[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll][^\n]{0,50},Kerberos,true,[^\n]{0,50},200,0,,,,[^\n]{0,2000};OnEndRequest\.End\.ContentType=application\/soap\+xml charset UTF-8;S:ServiceCommonMetadata\.HttpMethod=POST;/ ascii wide
		$fp1 = "ClientInfo" ascii wide fullword
		$fp2 = "Microsoft WinRM Client" ascii wide fullword
		$fp3 = "Exchange BackEnd Probes" ascii wide fullword

	condition:
		$re1 and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_LOG_Proxynotshell_POC_CVE_2022_41040_Nov22 : CVE_2022_41040 CVE_2022_41082
{
	meta:
		description = "Detects logs generated after a successful exploitation using the PoC code against CVE-2022-41040 and CVE-2022-41082 (aka ProxyNotShell) in Microsoft Exchange servers"
		author = "Florian Roth (Nextron Systems)"
		id = "1e47d124-3103-5bf5-946f-b1bb69ff2c8e"
		date = "2022-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/testanull/ProxyNotShell-PoC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/vuln_proxynotshell_cve_2022_41040.yar#L2-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "7f91502fd9c59180970fc4253134582b44ba318db03ef4eb575257b2f3818d94"
		score = 70
		quality = 85
		tags = "CVE-2022-41040, CVE-2022-41082"

	strings:
		$aa1 = " POST " ascii wide
		$aa2 = " GET " ascii wide
		$ab1 = " 200 " ascii wide
		$s01 = "/autodiscover.json x=a" ascii wide
		$s02 = "/autodiscover/admin@localhost/" ascii wide

	condition:
		1 of ( $aa* ) and $ab1 and 1 of ( $s* )
}

