rule TRELLIX_ARC_Sfx_Winrar_Plugx : BUILDER FILE
{
	meta:
		description = "Rule to detect the SFX WinRAR delivering a possible Plugx sample"
		author = "Marc Rivero | McAfee ATR Team"
		id = "ac975a58-6a8a-515e-b27f-327a7bfc7686"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_Operation_SoftCell.yar#L260-L307"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "8231f46330762cecf8a796d1a29c8fa6ba1c10b527fa86bf6c73130349558dad"
		score = 75
		quality = 68
		tags = "BUILDER, FILE"
		rule_version = "v1"
		malware_type = "builder"
		malware_family = "Builder:W32/Plugx"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
		$s2 = "Wrong password for %s5Write error in the file %s. Probably the disk is full" fullword wide
		$s3 = "mcutil.dll" fullword ascii
		$s4 = "Unexpected end of archiveThe file \"%s\" header is corrupt%The archive comment header is corrupt" fullword wide
		$s5 = "mcoemcpy.exe" fullword ascii
		$s6 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
		$s7 = "&Enter password for the encrypted file:" fullword wide
		$s8 = "start \"\" \"%CD%\\mcoemcpy.exe\"" fullword ascii
		$s9 = "setup.bat" fullword ascii
		$s10 = "ErroraErrors encountered while performing the operation" fullword wide
		$s11 = "Please download a fresh copy and retry the installation" fullword wide
		$s12 = "antivir.dat" fullword ascii
		$s13 = "The required volume is absent2The archive is either in unknown format or damaged" fullword wide
		$s14 = "=Total path and file name length must not exceed %d characters" fullword wide
		$s15 = "Please close all applications, reboot Windows and restart this installation\\Some installation files are corrupt." fullword wide
		$s16 = "folder is not accessiblelSome files could not be created." fullword wide
		$s17 = "Packed data CRC failed in %s" fullword wide
		$s18 = "DDTTDTTDTTDTTDTTDTTDTTDTTDTQ" fullword ascii
		$s19 = "File close error" fullword wide
		$s20 = "CRC failed in %s" fullword wide
		$op0 = { e8 6f 12 00 00 84 c0 74 04 32 c0 eb 34 56 ff 75 }
		$op1 = { 53 68 b0 34 41 00 57 e8 61 44 00 00 57 e8 31 44 }
		$op2 = { 56 ff 75 08 8d b5 f4 ef ff ff e8 17 ff ff ff 8d }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( pe.imphash ( ) == "dbb1eb5c3476069287a73206929932fd" and all of them )
}

