rule TRELLIX_ARC_Malw_Inabot_Worm : WORM FILE
{
	meta:
		description = "Rule to detect inabot worm based on PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "b899d2d6-000a-5363-9efe-527dcd0cea17"
		date = "2013-04-19"
		modified = "2020-08-14"
		reference = "http://verwijderspyware.blogspot.com/2013/04/elimineren-w32inabot-worm-hoe-te.html"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_inabot_worm_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "c9c010228254aae222e31c669dda639cdd30695729b8ef2b6ece06d899a496aa"
		logic_hash = "70485de4e071b684faa87484ce2a53a8b2a29d0a2954e785b858c7ff1d908de0"
		score = 75
		quality = 70
		tags = "WORM, FILE"
		rule_version = "v1"
		malware_type = "worm"
		malware_family = "Worm:W32/Inabot"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\trasser\\portland.pdb"
		$pdb1 = "\\mainstream\\archive.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 180KB and any of them
}

