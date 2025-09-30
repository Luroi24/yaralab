rule SIGNATURE_BASE_APT_Hiddencobra_Enc_PK_Header : HIDDEN_COBRA TYPEFRAME FILE
{
	meta:
		description = "Hidden Cobra - Detects trojan with encrypted header"
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		id = "5d7001b3-162c-5a97-a740-1b8e33d4aa9e"
		date = "2018-04-12"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_ar18_165a.yar#L2-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "d0c8345b69e5f421fd93bc239031f2e51a120ae64be1eca0c1fdae2aa55ac42a"
		score = 75
		quality = 85
		tags = "HIDDEN_COBRA, TYPEFRAME, FILE"
		incident = "10135536"
		category = "hidden_cobra"
		family = "TYPEFRAME"
		hash0 = "3229a6cea658b1b3ca5ca9ad7b40d8d4"

	strings:
		$s0 = { 5f a8 80 c5 a0 87 c7 f0 9e e6 }
		$s1 = { 95 f1 6e 9c 3f c1 2c 88 a0 5a }
		$s2 = { ae 1d af 74 c0 f5 e1 02 50 10 }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and any of them
}

rule SIGNATURE_BASE_APT_Hiddencobra_Import_Obfuscation_2 : HIDDEN_COBRA TYPEFRAME FILE
{
	meta:
		description = "Hidden Cobra - Detects remote access trojan"
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		id = "bc139580-a55b-514f-8a4e-ca1402ce3ad9"
		date = "2018-04-12"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_ar18_165a.yar#L21-L41"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "d52fc053afc6b3beb35a6dfd0f9b3714a5bad4e9b0dcfcce7be87d65f0a0c23e"
		score = 75
		quality = 85
		tags = "HIDDEN_COBRA, TYPEFRAME, FILE"
		incident = "10135536"
		category = "hidden_cobra"
		family = "TYPEFRAME"
		hash0 = "bfb41bc0c3856aa0a81a5256b7b8da51"

	strings:
		$s0 = {A6 D6 02 EB 4E B2 41 EB C3 EF 1F}
		$s1 = {B6 DF 01 FD 48 B5 }
		$s2 = {B6 D5 0E F3 4E B5 }
		$s3 = {B7 DF 0E EE }
		$s4 = {B6 DF 03 FC }
		$s5 = {A7 D3 03 FC }

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and all of them
}

rule SIGNATURE_BASE_APT_NK_AR18_165A_Hiddencobra_Import_Deob : HIDDEN_COBRA TYPEFRAME FILE
{
	meta:
		description = "Hidden Cobra - Detects installed proxy module as a service"
		author = "NCCIC trusted 3rd party - Edit: Tobias Michalski"
		id = "f403d589-be35-57a7-9675-f92657c11acc"
		date = "2018-04-12"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_ar18_165a.yar#L43-L60"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "ae769e62fef4a1709c12c9046301aa5d"
		hash = "e48fe20eblf5a5887f2ac631fed9ed63"
		logic_hash = "2eff83738ca4f2db8327c1ee2a9539d7ce882a315025a656d391c16079e432cb"
		score = 75
		quality = 85
		tags = "HIDDEN_COBRA, TYPEFRAME, FILE"
		incident = "10135536"
		category = "hidden_cobra"
		family = "TYPEFRAME"

	strings:
		$ = { 8a 01 3c 62 7c 0a 3c 79 7f 06 b2 db 2a d0 88 11 8a 41 01 41 84 c0 75 e8}
		$ = { 8A 08 80 F9 62 7C 0B 80 F9 79 7F 06 82 DB 2A D1 88 10 8A 48 01 40 84 C9 75 E6}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and any of them
}

