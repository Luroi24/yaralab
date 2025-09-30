rule SIGNATURE_BASE_EXPL_LNX_CUPS_CVE_2024_47177_Sep24 : CVE_2024_47177 FILE
{
	meta:
		description = "Detects exploit code for CUPS CVE-2024-47177"
		author = "Florian Roth"
		id = "a7b986ad-e943-5350-a6e0-34c40f07874c"
		date = "2024-09-27"
		modified = "2024-12-12"
		reference = "https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cups_sep24.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "633314dea5e3cbdf3cef6e4f18c2efca261dfc600bb9c11d0834fdae102ac9e6"
		score = 75
		quality = 85
		tags = "CVE-2024-47177, FILE"

	strings:
		$s1 = "FoomaticRIPCommandLine: " ascii
		$s2 = "cupsFilter2 : " ascii

	condition:
		filesize < 400KB and all of them
}

rule SIGNATURE_BASE_SUSP_EXPL_LNX_CUPS_CVE_2024_47177_Sep24 : CVE_2024_47177
{
	meta:
		description = "Detects suspicious FoomaticRIPCommandLine command in printer config, which could be used to exploit CUPS CVE-2024-47177"
		author = "Florian Roth"
		id = "cb76f1c7-6dc0-5fed-a970-2a4890db46d3"
		date = "2024-09-27"
		modified = "2024-12-12"
		reference = "https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cups_sep24.yar#L17-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "2158ca8a08cb7552e2a437de025e3aad63ddc5417245e6ede7283d3bd0fc159b"
		score = 65
		quality = 85
		tags = "CVE-2024-47177"

	strings:
		$ = "FoomaticRIPCommandLine: \"bash " ascii
		$ = "FoomaticRIPCommandLine: \"sh " ascii
		$ = "FoomaticRIPCommandLine: \"python " ascii
		$ = "FoomaticRIPCommandLine: \"perl " ascii
		$ = "FoomaticRIPCommandLine: \"echo " ascii
		$ = "FoomaticRIPCommandLine: \\\"bash " ascii
		$ = "FoomaticRIPCommandLine: \\\"sh " ascii
		$ = "FoomaticRIPCommandLine: \\\"python " ascii
		$ = "FoomaticRIPCommandLine: \\\"perl " ascii
		$ = "FoomaticRIPCommandLine: \\\"echo " ascii

	condition:
		1 of them
}

