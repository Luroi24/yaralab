rule SIGNATURE_BASE_LOG_EXPL_Adselfservice_CVE_2021_40539_ADSLOG_Sep21 : LOG CVE_2021_40539 FILE
{
	meta:
		description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
		author = "Florian Roth (Nextron Systems)"
		id = "156317c6-e726-506d-8b07-4f74dae2807f"
		date = "2021-09-20"
		modified = "2023-12-05"
		reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_adselfservice_cve_2021_40539.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "49b7857187c15f48e928747266adca44c227964cef72914616ea269b0e88fe73"
		score = 70
		quality = 85
		tags = "LOG, CVE-2021-40539, FILE"

	strings:
		$x1 = "Java traceback errors that include references to NullPointerException in addSmartCardConfig or getSmartCardConfig" ascii wide

	condition:
		filesize < 50MB and 1 of them
}

rule SIGNATURE_BASE_LOG_EXPL_Adselfservice_CVE_2021_40539_Weblog_Sep21_1 : LOG CVE_2021_40539 FILE
{
	meta:
		description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
		author = "Florian Roth (Nextron Systems)"
		id = "015957a6-8778-5836-af94-6e6d3838f693"
		date = "2021-09-20"
		modified = "2023-12-05"
		reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_adselfservice_cve_2021_40539.yar#L16-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "bc27afd63d32ac95711e5b4e70764fe0d1bcbb4b4b9b4e3f324e058bba2ef8f6"
		score = 60
		quality = 85
		tags = "LOG, CVE-2021-40539, FILE"

	strings:
		$x1 = "/ServletApi/../RestApi/LogonCustomization" ascii wide
		$x2 = "/ServletApi/../RestAPI/Connection" ascii wide

	condition:
		filesize < 50MB and 1 of them
}

