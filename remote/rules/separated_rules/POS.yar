rule TRELLIX_ARC_MALWARE_Blackpos_Pdb : POS FILE
{
	meta:
		description = "BlackPOS PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "f37e1522-49c4-5369-bc2c-33b070e9eae7"
		date = "2014-01-24"
		modified = "2020-08-14"
		reference = "https://en.wikipedia.org/wiki/BlackPOS_Malware"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_blackpos_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "5a963e8aca62f3cf5872c6bff02d6dee0399728554c6ac3f5cb312b2ba7d7dbf"
		logic_hash = "d8f3fa380ca15f0fae432849b8c16cb8a0a9d1427d3e72fbf89cbbd63b0849c9"
		score = 75
		quality = 70
		tags = "POS, FILE"
		rule_version = "v1"
		malware_type = "pos"
		malware_family = "Pos:W32/BlackPos"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Projects\\Rescator\\MmonNew\\Debug\\mmon.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and any of them
}

rule TRELLIX_ARC_Alina_POS_PDB : POS FILE
{
	meta:
		description = "Rule to detect Alina POS"
		author = "Marc Rivero | McAfee ATR Team"
		id = "9588aa10-d5e4-55f4-998c-a01503a53d3a"
		date = "2013-08-08"
		modified = "2020-08-14"
		reference = "https://www.pandasecurity.com/mediacenter/pandalabs/alina-pos-malware/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_alina_pos_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "28b0c52c0630c15adcc857d0957b3b8002a4aeda3c7ec40049014ce33c7f67c3"
		logic_hash = "9bb8260e3a47567e2460dd474fb74e57987e3d79eb30cdbc2a45b88a16ba1ca2"
		score = 75
		quality = 70
		tags = "POS, FILE"
		rule_version = "v1"
		malware_type = "pos"
		malware_family = "Pos:W32/Alina"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\Users\\dice\\Desktop\\SRC_adobe\\src\\grab\\Release\\Alina.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and any of them
}

rule TRELLIX_ARC_Kartoxa_Malware_Pdb : POS FILE
{
	meta:
		description = "Rule to detect Kartoxa POS based on the PDB"
		author = "Marc Rivero | McAfee ATR Team"
		id = "3d2dbf22-5d8f-5f19-9048-2d021ada22c8"
		date = "2010-10-09"
		modified = "2020-08-14"
		reference = "https://securitynews.sonicwall.com/xmlpost/guatambu-new-multi-component-infostealer-drops-kartoxa-pos-malware-apr-08-2016/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_backdoor_katorxa_pdb.yar#L1-L25"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "86dd21b8388f23371d680e2632d0855b442f0fa7e93cd009d6e762715ba2d054"
		logic_hash = "6e1810af386f3aada4cd1d72f76d8210d201808c8fe1d21d379ff1a825d93710"
		score = 75
		quality = 70
		tags = "POS, FILE"
		rule_version = "v1"
		malware_type = "pos"
		malware_family = "Pos:W32/Kartoxa"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$pdb = "\\vm\\devel\\dark\\mmon\\Release\\mmon.pdb"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and any of them
}

