rule SIGNATURE_BASE_VULN_Confluence_Questions_Plugin_CVE_2022_26138_Jul22_1 : CVE_2022_26138
{
	meta:
		description = "Detects properties file of Confluence Questions plugin with static user name and password (backdoor) CVE-2022-26138"
		author = "Florian Roth (Nextron Systems)"
		id = "1443c673-2a86-5431-876a-c8fccba52190"
		date = "2022-07-21"
		modified = "2023-12-05"
		reference = "https://www.bleepingcomputer.com/news/security/atlassian-fixes-critical-confluence-hardcoded-credentials-flaw/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/vul_confluence_questions_plugin_cve_2022_26138.yar#L2-L23"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "c164bd3d9ed1e155d51112e14340b814f6ea782604540c84a6e9efb5c6041156"
		score = 50
		quality = 85
		tags = "CVE-2022-26138"

	strings:
		$x_plain_1 = "predefined.user.password=disabled1system1user6708"
		$jar_marker = "/confluence/plugins/questions/"
		$jar_size_1 = { 00 CC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
      /*    here starts default.properties v                          */
                      ?? ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74 2E 70
                      72 6F 70 65 72 74 69 65 73 50 4B }
		$jar_size_2 = { 00 CC 00 ?? ?? ?? ?? ?? 00 64 65 66 61 75 6C 74
                      2E 70 72 6F 70 65 72 74 69 65 73 }

	condition:
		1 of ( $x* ) or ( $jar_marker and 1 of ( $jar_size* ) )
}

