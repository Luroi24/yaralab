rule SECUINFRA_DROPPER_Vjw0Rm_Stage_1 : JAVASCRIPT DROPPER VJW0RM FILE
{
	meta:
		description = "No description has been set in the source file - SecuInfra"
		author = "SECUINFRA Falcon Team"
		id = "a07f80e4-56c3-5b75-be64-648bc1fde964"
		date = "2022-02-19"
		modified = "2022-02-27"
		reference = "https://bazaar.abuse.ch/browse.php?search=tag%3AVjw0rm"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/Vjw0rm.yar#L2-L19"
		license_url = "N/A"
		logic_hash = "e5cc23431239e8a650369729050809cf6fe2acc58941086f79ce004b4f506eed"
		score = 75
		quality = 20
		tags = "JAVASCRIPT, DROPPER, VJW0RM, FILE"
		version = "0.1"

	strings:
		$a1 = "$$$"
		$a2 = "microsoft.xmldom"
		$a3 = "eval"
		$a4 = "join(\"\")"

	condition:
		( uint16( 0 ) == 0x7566 or uint16( 0 ) == 0x6176 or uint16( 0 ) == 0x0a0d or uint16( 0 ) == 0x660a ) and filesize < 60KB and all of ( $a* )
}

