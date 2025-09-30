rule TRELLIX_ARC_Jatboss : PHISHING FILE
{
	meta:
		description = "Rule to detect PDF files from Jatboss campaign and MSG files that contained those attachents"
		author = "Marc Rivero | McAfee ATR Team"
		id = "009a7486-2ee8-57ef-8dfd-fcbd035b4e85"
		date = "2019-12-04"
		modified = "2020-08-14"
		reference = "https://exchange.xforce.ibmcloud.com/collection/JATBOSS-Phishing-Kit-17c74b38860de5cb9fc727e6c0b6d5b5"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/malware/MALW_jatboss.yar#L1-L36"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		hash = "b81fb37dc48812f6ad61984ecf2a8dbbfe581120257cb4becad5375a12e755bb"
		logic_hash = "5e6e4c8f6c0896623f166a98eb83a9a4f23139306671cf2e35ba239b2dc191fc"
		score = 75
		quality = 66
		tags = "PHISHING, FILE"
		rule_version = "v1"
		malware_type = "phishing"
		malware_family = "Phishing:W32/Jatboss"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$jat = { 3C 3C 2F 41 75 74 68 6F 72 28 4A 41 54 29 20 2F 43 72 65 61 74 6F 72 28 }
		$jatboss = { 3C 3C 2F 41 75 74 68 6F 72 28 4A 41 54 29 20 2F 43 72 65 61 74 6F 72 28 }
		$spam = { 54 00 68 00 69 00 73 00 20 00 65 00 2D 00 6D 00 61 00 69 00 6C 00 20 00 61 00 6E 00 64 00 20 00 61 00 6E 00 79 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 6D 00 65 00 6E 00 74 00 20 00 61 00 72 00 65 00 20 00 43 00 6F 00 6E 00 66 00 69 00 64 00 65 00 6E 00 74 00 69 00 61 00 6C 00 2E 00 }

	condition:
		( uint16( 0 ) == 0x5025 and filesize < 1000KB and ( $jat or $jatboss ) ) or ( uint16( 0 ) == 0xcfd0 and $spam and any of ( $jat* ) )
}

rule SIGNATURE_BASE_Brooxml_Phishing : PHISHING
{
	meta:
		description = "Detects PDF and OOXML files leading to AiTM phishing"
		author = "Proofpoint"
		id = "ccd8ab30-90a4-5d4b-8a77-dbc4669bdb95"
		date = "2024-11-27"
		modified = "2024-12-12"
		reference = "https://x.com/threatinsight/status/1861817946508763480"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_brooxml_dec24.yar#L41-L56"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "5cc7bc1383e1ded8e8613cbb4fad003e35b67059ca70d33f29406a5c146a5464"
		score = 65
		quality = 31
		tags = "PHISHING"
		category = "phishing"

	strings:
		$hex1 = { 21 20 03 20 c3 be c3 bf 09 20 [0-1] 06 20 20 20 20 20 20 20 20 20 20 20 01 20 20 20 06 20 20 20 20 20 20 20 20 10 20 20 05 20 20 20 01 20 20 20 c3 be c3 bf c3 bf c3 bf }
		$docx = { 50 4b }
		$pdf = { 25 50 44 46 2d }

	condition:
		all of ( $hex* ) and ( ( $docx at 0 ) or ( $pdf at 0 ) )
}

