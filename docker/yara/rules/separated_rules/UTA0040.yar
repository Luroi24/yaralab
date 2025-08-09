rule VOLEXITY_Apt_Ico_Uta0040_B64_C2 : UTA0040 FILE
{
	meta:
		description = "Detection of malicious ICO files used in 3CX compromise."
		author = "threatintel@volexity.com"
		id = "1efb6376-a362-5f03-b4d3-08cd7d634de6"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-03-30 3CX/indicators/rules.yar#L1-L31"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "2667a36ce151c6e964f9ce9a6f587eedbffdd6ec76e451a23c5cfdd08248d15e"
		score = 75
		quality = 80
		tags = "UTA0040, FILE"
		hash1 = "a541e5fc421c358e0a2b07bf4771e897fb5a617998aa4876e0e1baa5fbb8e25c"
		memory_suitable = 0
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$IEND_dollar = {49 45 4e 44 ae 42 60 82 24}
		$IEND_nodollar = {49 45 4e 44 ae 42 60 82 }

	condition:
		uint16be( 0 ) == 0x0000 and filesize < 120KB and ( $IEND_dollar in ( filesize -500 .. filesize ) and not $IEND_nodollar in ( filesize -20 .. filesize ) and for any k in ( 1 .. #IEND_dollar ) : ( for all i in ( 1 .. 4 ) : ( uint8( @IEND_dollar [ k ] + !IEND_dollar [ k ] + i ) < 123 and uint8( @IEND_dollar [ k ] + !IEND_dollar [ k ] + i ) > 47 ) ) )
}

rule VOLEXITY_Apt_Mac_Iconic : UTA0040
{
	meta:
		description = "Detects the MACOS version of the ICONIC loader."
		author = "threatintel@volexity.com"
		id = "6d702ed3-e5b9-5324-a06b-507c9231cc00"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-03-30 3CX/indicators/rules.yar#L32-L50"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "7b689c3931632b01869ac2f21a1edca0a5ca9007299fe7cd16962d6866c27558"
		score = 75
		quality = 80
		tags = "UTA0040"
		hash1 = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$str1 = "3CX Desktop App" xor(0x01-0xff)
		$str2 = "__tutma=" xor(0x01-0xff)
		$str3 = "Mozilla/5.0" xor(0x01-0xff)

	condition:
		all of them
}

rule VOLEXITY_Apt_Win_Iconicstealer : UTA0040
{
	meta:
		description = "Detect the ICONICSTEALER malware family."
		author = "threatintel@volexity.com"
		id = "d7896506-6ce5-59b1-b24a-87ffdb2a5174"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-03-30 3CX/indicators/rules.yar#L51-L69"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "ed7731d2361e7d96a6a35f8359b61a2af049b16bc457cf870db8831e142aebe2"
		score = 75
		quality = 80
		tags = "UTA0040"
		hash1 = "8ab3a5eaaf8c296080fadf56b265194681d7da5da7c02562953a4cb60e147423"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$str1 = "\\3CXDesktopApp\\config.json" wide
		$str2 = "url, title FROM urls" wide
		$str3 = "url, title FROM moz_places" wide

	condition:
		all of them
}

rule VOLEXITY_Apt_Win_Iconic : UTA0040
{
	meta:
		description = "Detect the ICONIC loader."
		author = "threatintel@volexity.com"
		id = "e7d6fcc0-c830-5236-90fb-182c66873903"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-03-30 3CX/indicators/rules.yar#L70-L93"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "b62b1543c9af3afb8fc885f313e1a5d2fcb688657e3807cce72b31b56381681e"
		score = 75
		quality = 55
		tags = "UTA0040"
		hash1 = "f79c3b0adb6ec7bcc8bc9ae955a1571aaed6755a28c8b17b1d7595ee86840952"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$internal_name = "samcli.dll"
		$str1 = "gzip, deflate, br"
		$str2 = "__tutma"
		$str3 = "__tutmc"
		$str4 = "ChainingModeGCM" wide
		$str5 = "ChainingMode" wide
		$str6 = "icon%d.ico" wide

	condition:
		all of them
}

rule VOLEXITY_Apt_Win_3Cx_Backdoored_Lib : UTA0040
{
	meta:
		description = "Detects the malicious library delivered in the backdoored 3CX installer."
		author = "threatintel@volexity.com"
		id = "39270b93-830e-598f-a38e-fcc5050e4d30"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-03-30 3CX/indicators/rules.yar#L94-L133"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "40be2d46a318ff03724ea1f6628d78001c14c85a3ae6d032c0324ea849d707f2"
		score = 75
		quality = 80
		tags = "UTA0040"
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$shellcode = {
                        44 8D 4A ??
                        44 8D 92 ?? ?? ?? ??
                        45 85 C9
                        45 0F 49 D1
                        41 81 E2 00 FF FF FF
                        41 F7 DA
                        44 01 D2
                        FF C2
                        4C 63 CA
                        46 8A 94 0C ?? ?? ?? ??
                        45 00 D0
                        45 0F B6 D8
                        42 8A AC 1C ?? ?? ?? ??
                        46 88 94 1C ?? ?? ?? ??
                        42 88 AC 0C ?? ?? ?? ??
                        42 02 AC 1C ?? ?? ?? ??
                        44 0F B6 CD
                        46 8A 8C 0C ?? ?? ?? ??
                        45 30 0C 0E
                        48 FF C1
                        48 39 C8
                        75 ??
                }

	condition:
		all of them
}

rule VOLEXITY_Informational_Win_3Cx_Msi : UTA0040
{
	meta:
		description = "Detects 3CX installers created in March 2023, 3CX was known to be compromised at this time."
		author = "threatintel@volexity.com"
		id = "ac26e7b1-61eb-5074-bcda-46d714bdba4c"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-03-30 3CX/indicators/rules.yar#L134-L152"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "c04de2653ef587f27c7ebf058c6f6c345e16b67f36ccc4306bc49f8c4394728e"
		score = 75
		quality = 80
		tags = "UTA0040"
		hash1 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
		memory_suitable = 0
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$cert = { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 }
		$app = "3CXDesktopApp.exe"
		$data = "202303"

	condition:
		all of them
}

