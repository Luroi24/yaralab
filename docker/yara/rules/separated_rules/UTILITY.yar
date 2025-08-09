rule TRELLIX_ARC_Shadowspawn_Utility : UTILITY FILE
{
	meta:
		description = "Rule to detect ShadowSpawn utility used in the SoftCell operation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "0a325f5c-2750-5354-b920-f7e1510a8b71"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_Operation_SoftCell.yar#L3-L32"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "0f2805aee60cdb4eb932768849c845052c92131d0b25a511b822b79b2ac93e24"
		score = 75
		quality = 70
		tags = "UTILITY, FILE"
		rule_version = "v1"
		malware_type = "utility"
		malware_family = "Trojan:W32/ShadowSpawn"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$pdb = "C:\\data\\projects\\shadowspawn\\src\\bin\\Release-W2K3\\x64\\ShadowSpawn.pdb" fullword ascii
		$op0 = { e9 34 ea ff ff cc cc cc cc 48 8d 8a 20 }
		$op1 = { 48 8b 85 e0 06 00 00 48 8d 34 00 48 8d 46 02 48 }
		$op2 = { e9 34 c1 ff ff cc cc cc cc 48 8b 8a 68 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and ( pe.imphash ( ) == "eaae87b11d2ebdd286af419682037b4c" and all of them )
}

rule TRELLIX_ARC_Lg_Utility_Lateral_Movement_Softcell : UTILITY FILE
{
	meta:
		description = "Rule to detect the utility LG from Joeware to do Lateral Movement in the SoftCell operation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "4f435348-427a-5f35-9545-5582033eb043"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_Operation_SoftCell.yar#L108-L143"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "f88781b9632cd31bb9e3d68730c63c3fcd0ebe4a09b70b5b54d456cdc9ae8d01"
		score = 75
		quality = 70
		tags = "UTILITY, FILE"
		rule_version = "v1"
		malware_type = "utility"
		malware_family = "Utility:W32/Joeware"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "lg \\\\comp1\\users louise -add -r comp3" fullword ascii
		$s2 = "lg \\\\comp1\\users S-1-5-567-678-89765-456 -sid -add" fullword ascii
		$s3 = "lg \\\\comp1\\users -sidsout" fullword ascii
		$s4 = "Enumerates members of localgroup users on localhost" fullword ascii
		$s5 = "Adds SID resolved at comp3 for louise to localgroup users on comp1" fullword ascii
		$s6 = "CodeGear C++ - Copyright 2008 Embarcadero Technologies" fullword ascii
		$s7 = "Lists members of localgroup users on comp1 in SID format" fullword ascii
		$s8 = "ERROR: Verify that CSV lines are available in PIPE input. " fullword ascii
		$op0 = { 89 43 24 c6 85 6f ff ff ff 00 83 7b 24 10 72 05 }
		$op1 = { 68 f8 0e 43 00 e8 8d ff ff ff 83 c4 20 68 f8 0e }
		$op2 = { 66 c7 85 74 ff ff ff 0c 00 8d 55 d8 52 e8 e9 eb }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "327ce3f883a5b59e966b5d0e3a321156" and all of them )
}

rule TRELLIX_ARC_Nbtscan_Utility_Softcell : UTILITY FILE
{
	meta:
		description = "Rule to detect nbtscan utility used in the SoftCell operation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "a2a8dd43-0d30-5da5-9dd3-6ba9f6473c40"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_Operation_SoftCell.yar#L178-L209"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "6079f1363578f82fd38971d0c8f69cc156f7f678c3f2be22c5d9c3748dc80b1f"
		score = 75
		quality = 45
		tags = "UTILITY, FILE"
		rule_version = "v1"
		malware_type = "utility"
		malware_family = "Utility:W32/NbtScan"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "nbtscan 1.0.35 - 2008-04-08 - http://www.unixwiz.net/tools/" fullword ascii
		$s2 = "parse_target_cb.c" fullword ascii
		$s3 = "ranges. Ranges can be in /nbits notation (\"192.168.12.0/24\")" fullword ascii
		$s4 = "or with a range in the last octet (\"192.168.12.64-97\")" fullword ascii
		$op0 = { 52 68 d4 66 40 00 8b 85 58 ff ff ff 50 ff 15 a0 }
		$op1 = { e9 1c ff ff ff 8b 45 fc 8b e5 5d c3 cc cc cc cc }
		$op2 = { 59 59 c3 8b 65 e8 ff 75 d0 ff 15 34 60 40 00 ff }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and ( pe.imphash ( ) == "2fa43c5392ec7923ababced078c2f98d" and all of them )
}

