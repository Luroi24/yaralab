rule ELCEEF_Winrar_CVE_2023_38831_Exploit : CVE_2023_38831 FILE
{
	meta:
		description = "Detects ZIP archives exploiting CVE-2023-38831 in WinRAR"
		author = "marcin@ulikowski.pl"
		id = "7d592eb7-b344-59ed-adf8-fe69ebb1e43f"
		date = "2023-09-23"
		modified = "2023-09-28"
		reference = "https://www.group-ib.com/blog/cve-2023-38831-winrar-zero-day"
		source_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/rules/WinRAR_CVE_2023_38831.yara#L1-L17"
		license_url = "https://github.com/elceef/yara-rulz/blob/05834717d1464d5efce8ad9d688ff7b53886a0bb/LICENSE"
		logic_hash = "06f1d807429fb175831cf333b05b44b6ce33b4ae981e16c03e36ec7564a4fdd1"
		score = 75
		quality = 75
		tags = "CVE-2023-38831, FILE"
		hash1 = "00175d538cba0c493e397a0b7f4b28f9a90dd0ee40f69795ae28d23ce0d826c0"
		hash2 = "ca8ca67df7853b86b6a107c8fd7f73b757de9143ea8844d0e6209249e8377885"

	strings:
		$ = { 50 4b 03 04 [24] 00 00 [3-64] 2e ?? ?? ?? 20 2f [3-64] 2e ?? ?? ?? 20 2e ( 626174 | 636d64 | 707331 ) }

	condition:
		uint16be( 0 ) == 0x504b and all of them
}

rule SEKOIA_Loader_Win_Piccassoloader : CVE_2023_38831
{
	meta:
		description = "Detect the variant of Picasso used by GhostWriter as CVE-2023-38831 exploitation payload"
		author = "Sekoia.io"
		id = "91d9c2de-451e-467e-8f5c-38bbcce92b72"
		date = "2023-09-07"
		modified = "2024-12-19"
		reference = "https://github.com/SEKOIA-IO/Community"
		source_url = "https://github.com/SEKOIA-IO/Community/blob/a47734fa931e56f8646dab2abf31629431982429/yara_rules/loader_win_piccassoloader.yar#L1-L16"
		license_url = "https://github.com/SEKOIA-IO/Community/blob/a47734fa931e56f8646dab2abf31629431982429/LICENSE.md"
		logic_hash = "93e598f6c70dcb1ddf20ea926af72241e135bdf910f3721a7a0c3036f6a3d1b9"
		score = 75
		quality = 76
		tags = "CVE-2023-38831"
		version = "1.0"
		classification = "TLP:CLEAR"

	strings:
		$ = {2c 27 44 65 63 72 79 70 74 6f 72 27 2c 27 6e 6f 64 65 27 2c 27 55 73 65 72 2d}
		$ = {5c 78 32 30 43 68 72 6f 6d 65 2f 31 30 27 2c 27 67 67 65 72 27 2c 27 73 65 64 43 69 70 68 65 72 27 2c 27 5f 61 70 70 65 6e 64 27 2c 27 5f 45 4e 43 5f 58 46 4f 52 4d 27 2c 27 57 53 63 72 69 70 74 2e 53 68 27}

	condition:
		1 of them
}

