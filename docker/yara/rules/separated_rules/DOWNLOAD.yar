rule SECUINFRA_SUSP_Powershell_Download_Temp_Rundll : POWERSHELL DOWNLOAD FILE
{
	meta:
		description = "Detect a Download to %temp% and execution with rundll32.exe"
		author = "SECUINFRA Falcon Team"
		id = "6b09a6f0-29c6-5baf-ae64-7aa49a37a9d3"
		date = "2022-09-02"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/powershell.yar#L1-L17"
		license_url = "N/A"
		logic_hash = "4d7860dc94614b10bc0eea0189ad9b964399d4ee6404ebeaef40720c716c592d"
		score = 65
		quality = 70
		tags = "POWERSHELL, DOWNLOAD, FILE"

	strings:
		$location = "$Env:temp" nocase
		$download = "downloadfile(" nocase
		$rundll = "rundll32.exe"

	condition:
		filesize < 100KB and $location and $download and $rundll
}

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

rule SECUINFRA_SUSP_DOTNET_PE_Download_To_Specialfolder : DOTNET DOWNLOAD FILE
{
	meta:
		description = "Detects a .NET Binary that downloads further payload and retrieves a special folder"
		author = "SECUINFRA Falcon Team"
		id = "106683bf-1d36-58ee-b5af-4723aa70fdad"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Filetypes/exe.yar#L45-L64"
		license_url = "N/A"
		logic_hash = "d44c89ab126f79596c8bf3f1327b37a2463faa4e3bb258f9a96d495ac40003f8"
		score = 65
		quality = 70
		tags = "DOTNET, DOWNLOAD, FILE"

	strings:
		$special_folder = "Environment.SpecialFolder" wide
		$webclient = "WebClient()" wide
		$download = ".DownloadFile(" wide

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and pe.imports ( "mscoree.dll" ) and $special_folder and $webclient and $download
}

rule SECUINFRA_SUSP_Powershell_Download_Temp_Rundll_1 : POWERSHELL DOWNLOAD
{
	meta:
		description = "Detect a Download to %temp% and execution with rundll32.exe"
		author = "SECUINFRA Falcon Team"
		id = "f7a9d2e6-bebf-598b-9e59-db0a3001b9f9"
		date = "2022-09-02"
		modified = "2022-02-19"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/PowerShell_Misc/download_variations.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "7982438c032127349fb1c3477a23bab1c92eb68d9c3b26e2f5fb0a8c332dbc44"
		score = 65
		quality = 70
		tags = "POWERSHELL, DOWNLOAD"

	strings:
		$location = "$Env:temp" nocase
		$download = "downloadfile(" nocase
		$rundll = "rundll32.exe"

	condition:
		$location and $download and $rundll
}

