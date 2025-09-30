rule R3C0NST_ATM_Malware_Ripper : ATMRIPPER MALWARE FILE
{
	meta:
		description = "Rule detects Thailand ATM Jackpot malware RIPPER (unpacked)"
		author = "Frank Boldewin"
		id = "38dfda5b-45cc-55d4-b619-91fa31c09a09"
		date = "2016-08-01"
		modified = "2019-02-27"
		reference = "https://github.com/fboldewin/YARA-rules/"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/ATM.Malware.Ripper.yar#L1-L22"
		license_url = "N/A"
		logic_hash = "bb7b474330defe6d071b9595687d4510961055fa243a26306698c1e029a935f1"
		score = 75
		quality = 90
		tags = "ATMRIPPER, MALWARE, FILE"
		malware_family = "ATM-malware RIPPER"

	strings:
		$Card_Hash1 = "be59a724feae790b3f315edf71a8450888c021f113e3c2b471e174130c201852" nocase ascii
		$Card_Hash2 = "f26a57da928d6f3e3480dfc7d03761161191bdb170e10ca15c7ac5de6912945c" nocase ascii
		$Card_Hash3 = "692cdaf6e42ab3a4f307e5d047249f7b30ceddd6bc88f22ca032412419bd62b7" nocase ascii
		$Card_Hash4 = "0679c7c0c9b0d6919c12cbc087e942d7bf48d3a78cd3ec80321fbfd1b33a1904" nocase ascii
		$Code_Bytes1 = { 68 CB 00 00 00 50 FF 15 ?? ?? ?? ?? EB 19 }
		$Code_Bytes2 = { E8 ?? ?? ?? ?? 83 C4 18 6A 02 53 53 FF 15 ?? ?? ?? ?? 68 74 12 43 00 8D 55 A4 }
		$Service = "DBACKUP SERVICE" nocase wide

	condition:
		uint16( 0 ) == 0x5A4D and uint32( uint32( 0x3C ) ) == 0x00004550 and 2 of ( $Card_Hash* ) and all of ( $Code_Bytes* ) and filesize < 400KB and ( $Service in ( 0x2f000 .. 0x30000 ) )
}

