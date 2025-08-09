rule SECUINFRA_SUSP_Discord_Attachments_URL : PE DOWNLOAD FILE
{
	meta:
		description = "Detects a PE file that contains an Discord Attachments URL. This is often used by Malware to download further payloads"
		author = "SECUINFRA Falcon Team"
		id = "bf81920b-f8ab-594a-aa45-d92446411113"
		date = "2022-02-19"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/exe.yar#L3-L16"
		license_url = "N/A"
		logic_hash = "3270b74506e520064361379b274f44a467c55bdcd3d8456967e864526aca8521"
		score = 65
		quality = 70
		tags = "PE, DOWNLOAD, FILE"
		version = "0.1"

	strings:
		$url = "cdn.discordapp.com/attachments" nocase wide

	condition:
		uint16( 0 ) == 0x5a4d and $url
}

rule SECUINFRA_SUSP_Netsh_Firewall_Command : PE FILE
{
	meta:
		description = "No description has been set in the source file - SecuInfra"
		author = "SECUINFRA Falcon Team"
		id = "c62cbe3f-9585-56c0-bb09-83a36437abda"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/exe.yar#L84-L97"
		license_url = "N/A"
		logic_hash = "7d19b433785684ce1d2b008b3fdd36b22c5c82bfec476c787dfa025080b6178d"
		score = 65
		quality = 70
		tags = "PE, FILE"

	strings:
		$netsh_delete = "netsh firewall delete" wide
		$netsh_add = "netsh firewall add" wide

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( $netsh_delete or $netsh_add )
}

rule SIGNATURE_BASE_MAL_CRIME_Suspicious_Hex_String_Jun21_1 : CRIME PE FILE
{
	meta:
		description = "Triggers on parts of a big hex string available in lots of crime'ish PE files."
		author = "Nils Kuhnert"
		id = "2ad208fa-c7a5-5df9-96fe-4a84dc770f0f"
		date = "2021-06-04"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/mal_crime_unknown.yar#L1-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "73144b14f3aa1a1d82df7710fa47049426bfbddeef75e85c8a0a559ad6ed05a3"
		score = 65
		quality = 85
		tags = "CRIME, PE, FILE"
		hash1 = "37d60eb2daea90a9ba275e16115848c95e6ad87d20e4a94ab21bd5c5875a0a34"
		hash2 = "3380c8c56d1216fe112cbc8f1d329b59e2cd2944575fe403df5e5108ca21fc69"
		hash3 = "cd283d89b1b5e9d2875987025009b5cf6b137e3441d06712f49e22e963e39888"
		hash4 = "404efa6fb5a24cd8f1e88e71a1d89da0aca395f82d8251e7fe7df625cd8e80aa"
		hash5 = "479bf3fb8cff50a5de3d3742ab4b485b563b8faf171583b1015f80522ff4853e"

	strings:
		$a1 = "07032114130C0812141104170C0412147F6A6A0C041F321104130C0412141104030C0412141104130C0412141104130C0412141104130C0412141104130C0412141104130C0412141104130C0412141122130C0412146423272A711221112B1C042734170408622513143D20262B0F323038692B312003271C170B3A2F286623340610241F001729210579223202642200087C071C17742417020620141462060F12141104130C0412141214001C0412011100160C0C002D2412130C0412141104130C04121A11041324001F140122130C0134171" ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 10MB and all of them
}

