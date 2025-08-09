rule SIGNATURE_BASE_MAL_BACKORDER_LOADER_WIN_Go_Jan23 : LOADER GOLANG BACKORDER MALWARE WINDOWS FILE
{
	meta:
		description = "Detects the BACKORDER loader compiled in GO which download and executes a second stage payload from a remote server."
		author = "Arda Buyukkaya (modified by Florian Roth)"
		id = "90a82f2c-be92-5d0b-b47e-f47db2b15867"
		date = "2025-01-23"
		modified = "2025-03-20"
		reference = "EclecticIQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/mal_win_go_backorder_loader.yar#L1-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "70c91ffdc866920a634b31bf4a070fb3c3f947fc9de22b783d6f47a097fec2d8"
		logic_hash = "9e79ec9e58e02b7660383ff20957b95bc3c61ed3badc9af3d5829ebe5bf6bd7b"
		score = 80
		quality = 85
		tags = "LOADER, GOLANG, BACKORDER, MALWARE, WINDOWS, FILE"

	strings:
		$GoBuildId = "Go build" ascii
		$x_DebugSymbol_1 = "C:/updatescheck/main.go"
		$x_DebugSymbol_2 = "C:/Users/IEUser/Desktop/Majestic/"
		$s_FunctionName_1 = "main.getUpdates.func"
		$s_FunctionName_2 = "main.obt_zip"
		$s_FunctionName_3 = "main.obtener_zip"
		$s_FunctionName_4 = "main.get_zip"
		$s_FunctionName_5 = "main.show_pr0gressbar"
		$s_FunctionName_6 = "main.pr0cess"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 10MB and $GoBuildId and ( 1 of ( $x* ) or 3 of them )
}

