rule SIGNATURE_BASE_APT_SAP_Netweaver_Exploitation_Activity_Apr25_1 : SCRIPT CVE_2025_31324 FILE
{
	meta:
		description = "Detects forensic artefacts related to exploitation activity of SAP NetWeaver CVE-2025-31324"
		author = "Florian Roth"
		id = "78863492-5c83-55a8-900b-057e99125414"
		date = "2025-04-25"
		modified = "2025-05-15"
		reference = "https://reliaquest.com/blog/threat-spotlight-reliaquest-uncovers-vulnerability-behind-sap-netweaver-compromise/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_sap_netweaver_apr25.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "ab6c5e17bba15a3f968bdbe88a8cf4a039c55b6035d91fd3c6b30092be89af5c"
		score = 70
		quality = 85
		tags = "SCRIPT, CVE-2025-31324, FILE"

	strings:
		$x01 = "/helper.jsp?cmd=" ascii wide
		$x02 = "/cache.jsp?cmd=" ascii wide

	condition:
		filesize < 20MB and 1 of them
}

rule SIGNATURE_BASE_APT_SAP_Netweaver_Exploitation_Activity_Apr25_2 : SCRIPT CVE_2025_31324 FILE
{
	meta:
		description = "Detects forensic artefacts related to exploitation activity of SAP NetWeaver CVE-2025-31324"
		author = "Florian Roth"
		id = "17fb236e-e78c-51e5-b0a8-14964e38dfc5"
		date = "2025-04-25"
		modified = "2025-05-15"
		reference = "https://reliaquest.com/blog/threat-spotlight-reliaquest-uncovers-vulnerability-behind-sap-netweaver-compromise/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_sap_netweaver_apr25.yar#L16-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "dfc24a4f359e2bc899ab3924bd342c2c6bd8c757b7c1d3859a47f61b9e4039a9"
		score = 70
		quality = 85
		tags = "SCRIPT, CVE-2025-31324, FILE"

	strings:
		$x03 = "MSBuild.exe c:\\programdata\\" ascii wide

	condition:
		filesize < 20MB and 1 of them
}

