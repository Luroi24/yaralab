rule SIGNATURE_BASE_Brooxml_Hunting : HUNTING FILE
{
	meta:
		description = "Detects Microsoft OOXML files with prepended data/manipulated header"
		author = "Proofpoint"
		id = "1ffea1c7-9f97-5bb1-93d7-ce914765416f"
		date = "2024-11-27"
		modified = "2024-12-12"
		reference = "https://x.com/threatinsight/status/1861817946508763480"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_brooxml_dec24.yar#L2-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "89da6056adbae6155e682b84b950db84e3aedbb9ae693118e6e09d9ed67b03dd"
		score = 70
		quality = 58
		tags = "HUNTING, FILE"
		category = "hunting"

	strings:
		$pk_ooxml_magic = {50 4b 03 04 [22] 13 00 [2] 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c}
		$pk_0102 = {50 4b 01 02}
		$pk_0304 = {50 4b 03 04}
		$pk_0506 = {50 4b 05 06}
		$pk_0708 = {50 4b 07 08}
		$word = "word/"
		$ole = {d0 cf 11 e0}
		$mz = {4d 5a}
		$tef = {78 9f 3e 22}

	condition:
		$pk_ooxml_magic in ( 4 .. 16384 ) and $pk_0506 in ( 16384 .. filesize ) and #pk_0506 == 1 and #pk_0102 > 2 and #pk_0304 > 2 and $word and not ( $pk_0102 at 0 ) and not ( $pk_0304 at 0 ) and not ( $pk_0506 at 0 ) and not ( $pk_0708 at 0 ) and not ( $ole at 0 ) and not ( $mz at 0 ) and not ( $tef at 0 )
}

rule SIGNATURE_BASE_APT_IN_TA397_Wmrat : HUNTING
{
	meta:
		description = "track wmRAT based on socket usage, odd error handling, and reused strings"
		author = "Proofpoint"
		id = "c5855b30-3e75-570f-b327-498dfc382159"
		date = "2024-11-20"
		modified = "2025-01-17"
		reference = "https://www.proofpoint.com/us/blog/threat-insight/hidden-plain-sight-ta397s-new-attack-chain-delivers-espionage-rats"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_ta397_dec24.yar#L2-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "3bf4bbd5564f4381820fb8da5810bd4d9718b5c80a7e8f055961007c6f30da2b"
		hash = "3e9a08972b8ec9c2e64eeb46ce1db92ae3c40bc8de48d278ba4d436fc3c8b3a4"
		hash = "40ddb4463be9d8131f363fd78e21d9de5d838a3ec4044526aea45a473d6ddd61"
		hash = "4836cb7eed0b20da50acb26472f918b180917101c026ce36074e0e879b604308"
		hash = "4e3e4d476810c95c34b6f2aa9c735f8e57e85e3b7a97c709adc5d6ee4a5f6ccc"
		hash = "5ab76cf85ade810b7ae449e3dff8a19a018174ced45d37062c86568d9b7633f9"
		hash = "811741d9df51a9f16272a64ec7eb8ff12f8f26794368b1ff4ad5d30a1f4bb42a"
		hash = "b588a423b826b57dce72c9ab58f89be2ddc710a0367ed0eed001c047d8bef32a"
		hash = "caf871247b7256945598816e9c5461d64b6bdb68a15ff9f8742ca31dc00865f8"
		logic_hash = "b20a13b87f4b81e7ebc10ff2f6203aeab46980e0d481bad786695339dd59bf7a"
		score = 75
		quality = 85
		tags = "HUNTING"
		category = "hunting"
		malfamily = "wmRAT"
		version = "1.0"

	strings:
		$code_sleep_loop = {
            6a 64              // push    0x64
            ff d6              // call    esi
            6a 01              // push    0x1
            e8 ?? ?? ?? ??     // call    operator new
            83 c4 04           // add     esp, 0x4
            3b c7              // cmp     eax, edi

        }
		$code_error_handling = {
            88 19           // mov     byte [ecx], bl
            4a              // dec     edx
            41              // inc     ecx
            47              // inc     edi
            4e              // dec     esi
            85 d2           // test    edx, edx
            ?? ??           // jne     0x401070
            5f              // pop     edi {__saved_edi}
            49              // dec     ecx
            5e              // pop     esi {__saved_esi}
            b8 7a 00 07 80  // mov     eax, 0x8007007a

        }
		$code_socket_recv_parsing = {
            // 8b 15 20 55 41 00   mov     edx, dword [data_415520]
            6a 00              // push    0x0
            b8 04 00 00 00     // mov     eax, 0x4
            2b c6              // sub     eax, esi
            50                 // push    eax {var_10_1}
            8d 0c 3e           // lea     ecx, [esi+edi]
            51                 // push    ecx {var_14_1}
            52                 // push    edx {var_18_1}
            ff ??              // call    ebx
            83 f8 ff           // cmp     eax, 0xffffffff
            ?? ??              // je      0x4082e3
            03 f0              // add     esi, eax
            83 fe 04           // cmp     esi, 0x4
          }
		$str1 = "-.-.-." ascii
		$str2 = "PATH" ascii
		$str3 = "Path=" ascii
		$str4 = "https://microsoft.com" ascii
		$str5 = "%s%ld M" ascii
		$str6 = "%s%ld K" ascii
		$str7 = "%s(%ld)" ascii
		$str8 = "RFOX" ascii
		$str9 = "1llll" ascii
		$str10 = "%d result(s)" ascii
		$str11 = "%s%ld MB" ascii
		$str12 = "%s%ld KB" ascii
		$str13 = "%.1f" ascii
		$str14 = "%02d-%02d-%d %02d:%02d" ascii

	condition:
		uint16be( 0x0 ) == 0x4d5a and ( 2 of ( $code* ) or 10 of ( $str* ) )
}

rule SIGNATURE_BASE_SUSP_RAR_NTFS_ADS : HUNTING FILE
{
	meta:
		description = "Detects RAR archive with NTFS alternate data stream"
		author = "Proofpoint"
		id = "ca2b5904-b3d3-53cd-a973-6f30f0831a94"
		date = "2024-12-17"
		modified = "2025-01-17"
		reference = "https://www.proofpoint.com/us/blog/threat-insight/hidden-plain-sight-ta397s-new-attack-chain-delivers-espionage-rats"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_ta397_dec24.yar#L82-L110"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "bcca4771e8f940ce8cfcff08284545fec6163df549e1fb589d89ca3fa335f04c"
		score = 70
		quality = 83
		tags = "HUNTING, FILE"
		category = "hunting"
		hash1 = "feec47858379c29300d249d1693f68dc085300f493891d1a9d4ea83b8db6e3c3"
		hash2 = "53a653aae9678075276bdb8ccf5eaff947f9121f73b8dcf24858c0447922d0b1"

	strings:
		$rar_magic = {52 61 72 21}
		$ads = {
                 03         // Header Type -> Service Header
                 23         // Header flags
                 [17-20]    // Flags and extra data area
                 00         // Windows
                 03         // Length of name = STM = 3
                 53 54 4d   // STM NTFS alternate data stream
                 [1-2]      // variable int (vint) for size of the stream name -> 1-2 bytes should be enough to take into account
                 07         // Data type = Service data = Service header data array
                 3a         // Start of the ADS name -> start with colon ":"
               }
		$neg = "Zone.Identifier"

	condition:
		$rar_magic at 0 and $ads and not $neg in ( @ads [ 1 ] .. @ads [ 1 ] + 15 )
}

