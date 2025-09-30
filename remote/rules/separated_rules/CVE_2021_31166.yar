rule SIGNATURE_BASE_EXPL_CVE_2021_31166_Accept_Encoding_May21_1 : CVE_2021_31166
{
	meta:
		description = "Detects malformed Accept-Encoding header field as used in code exploiting CVE-2021-31166"
		author = "Florian Roth (Nextron Systems)"
		id = "d0a79cdc-f3ee-58f9-805c-ec9eb7993315"
		date = "2021-05-21"
		modified = "2023-12-05"
		reference = "https://github.com/0vercl0k/CVE-2021-31166"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2021_31166.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "5bb5b4093a7abe9d4297a4c047803b92f7c08f56f15b0f7bd163203ae47e026d"
		score = 70
		quality = 60
		tags = "CVE-2021-31166"

	strings:
		$xr1 = /[Aa]ccept\-[Ee]ncoding: [a-z\-]{1,16},([a-z\-\s]{1,16},|)*[\s]{1,20},/

	condition:
		1 of them
}

