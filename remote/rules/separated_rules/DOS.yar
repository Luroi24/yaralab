rule TRELLIX_ARC_Chikdos_Malware_Pdb : DOS FILE
{
	meta:
		description = "Chikdos PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "0174ff2b-57fc-5578-b45e-c08bf8528ee8"
		date = "2013-12-02"
		modified = "2020-08-14"
		reference = "http://hackermedicine.com/tag/trojan-chickdos/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_chickdos_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "c2a0e9f8e880ac22098d550a74940b1d81bc9fda06cebcf67f74782e55e9d9cc"
		logic_hash = "150bf809a61aad00df0c49fb6a609b909c84ffb9ca442e143a6c5bf3dfc39314"
		score = 75
		quality = 70
		tags = "DOS, FILE"
		rule_version = "v1"
		malware_type = "dos"
		malware_family = "Dos:W32/ChickDos"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\IntergrateCHK\\Release\\IntergrateCHK.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and any of them
}

