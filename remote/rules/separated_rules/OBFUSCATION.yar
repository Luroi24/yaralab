rule COD3NYM_Eazfuscator_String_Encryption : SUSPICIOUS OBFUSCATION FILE
{
	meta:
		description = "Eazfuscator.NET string encryption"
		author = "Jonathan Peters"
		id = "09a400f5-e837-58c2-9b51-9213c8ab0883"
		date = "2024-01-01"
		modified = "2024-01-10"
		reference = "https://github.com/cod3nym/detection-rules/"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/malcat/obfuscators.yar#L1-L29"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		hash = "3a9ee09ed965e3aee677043ba42c7fdbece0150ef9d1382c518b4b96bbd0e442"
		logic_hash = "5f3f3358e3cfb274aa2e8465dde58a080f9fb282aa519885b9d39429521db6d9"
		score = 65
		quality = 80
		tags = "SUSPICIOUS, OBFUSCATION, FILE"
		name = "Eazfuscator"
		category = "obfuscation"
		reliability = 90
		tlp = "TLP:white"

	strings:
		$sa1 = "StackFrame" ascii
		$sa2 = "StackTrace" ascii
		$sa3 = "Enter" ascii
		$sa4 = "Exit" ascii
		$op1 = { 11 ?? 18 91 11 ?? 1? 91 1F 10 62 60 11 ?? 1? 91 1E 62 60 11 ?? 17 91 1F 18 62 60 }
		$op2 = { D1 28 ?? 00 00 0A 0? 1F 10 63 D1 }
		$op3 = { 1F 10 63 D1 28 [3] 0A }
		$op4 = { 7B ?? 00 00 04 16 91 02 7B ?? 00 00 04 17 91 1E 62 60 02 7B ?? 00 00 04 18 91 1F 10 62 60 02 7B ?? 00 00 04 19 91 1F 18 62 60 }

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $sa* ) and ( 2 of ( $op* ) or #op1 == 2 )
}

rule COD3NYM_Eazfuscator_Code_Virtualization : SUSPICIOUS OBFUSCATION FILE
{
	meta:
		description = "Eazfuscator.NET code virtualization"
		author = "Jonathan Peters"
		id = "d39bba65-1220-5b60-b919-1bd88f1bc7f1"
		date = "2024-01-01"
		modified = "2024-01-10"
		reference = "https://github.com/cod3nym/detection-rules/"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/malcat/obfuscators.yar#L31-L54"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		hash = "53d5c2574c7f70b7aa69243916acf6e43fe4258fbd015660032784e150b3b4fa"
		logic_hash = "7a647973eae9163cb5b82c27141956da58f4a9fd2ad51cf82523b93536cfaea3"
		score = 65
		quality = 80
		tags = "SUSPICIOUS, OBFUSCATION, FILE"
		name = "Eazfuscator"
		category = "obfuscation"
		reliability = 90
		tlp = "TLP:white"

	strings:
		$sa1 = "BinaryReader" ascii
		$sa2 = "GetManifestResourceStream" ascii
		$sa3 = "get_HasElementType" ascii
		$op1 = { 28 [2] 00 06 28 [2] 00 06 72 [2] 00 70 ?? 1? 2D 0? 26 26 26 26 2B }
		$op2 = { 7E [3] 04 2D 3D D0 [3] 02 28 [3] 0A 6F [3] 0A 72 [3] 70 6F [3] 0A 20 80 00 00 00 8D ?? 00 00 01 25 D0 [3] 04 28 [3] 0A 28 [3] 06 28 [3] 06 80 [3] 04 7E [3] 04 2A }
		$op3 = { 02 20 [4] 1F 09 73 [4] 7D [3] 04 }

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $sa* ) and 2 of ( $op* )
}

rule COD3NYM_Confuserex_Naming_Pattern : SUSPICIOUS OBFUSCATION FILE
{
	meta:
		description = "ConfuserEx Renaming Pattern"
		author = "Jonathan Peters"
		id = "2b57f135-9d9d-5401-be29-a1053f4249ec"
		date = "2024-01-03"
		modified = "2024-01-10"
		reference = "https://github.com/cod3nym/detection-rules/"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/malcat/obfuscators.yar#L56-L77"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		logic_hash = "f28f3bd61c6f257cc622f6f323a5b5113d7d7b79ce8b852df02c42af22ecf033"
		score = 65
		quality = 80
		tags = "SUSPICIOUS, OBFUSCATION, FILE"
		name = "ConfuserEx"
		category = "obfuscation"
		reliability = 90

	strings:
		$s1 = "mscoree.dll" ascii
		$s2 = "mscorlib" ascii
		$s3 = "System.Private.Corlib" ascii
		$s4 = "#Strings" ascii
		$s5 = { 5F 43 6F 72 [3] 4D 61 69 6E }
		$name_pattern = { E2 ( 80 8? | 81 AA ) E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 [2] E2 80 AE}

	condition:
		uint16( 0 ) == 0x5a4d and 2 of ( $s* ) and #name_pattern > 5
}

rule COD3NYM_Confuserex_Packer : SUSPICIOUS OBFUSCATION FILE
{
	meta:
		description = "ConfuserEx Packer"
		author = "Jonathan Peters"
		id = "cd53a62f-62e3-58a1-8bc3-7f40949e3f00"
		date = "2024-01-09"
		modified = "2024-01-10"
		reference = "https://github.com/cod3nym/detection-rules/"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/malcat/obfuscators.yar#L79-L99"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		logic_hash = "43aee4c01b47ca04ee516d418939ec3e90fd08566f2a4b501c4698b7f9e0225d"
		score = 65
		quality = 80
		tags = "SUSPICIOUS, OBFUSCATION, FILE"
		name = "ConfuserEx"
		category = "obfuscation"
		reliability = 90

	strings:
		$s1 = "GCHandle" ascii
		$s2 = "GCHandleType" ascii
		$op1 = { 5A 20 89 C0 3F 14 6A 5E [8-20] 5A 20 FB 56 4D 44 6A 5E 6D 9E }
		$op2 = { 20 61 FF 6F 00 13 ?? 06 13 ?? 16 13 [10-20] 20 1F 3F 5E 00 5A }
		$op3 = { 16 91 7E [3] 04 17 91 1E 62 60 7E [3] 04 18 91 1F 10 62 60 7E [3] 04 19 91 1F 18 62 }

	condition:
		uint16( 0 ) == 0x5a4d and all of ( $s* ) and 2 of ( $op* )
}

rule COD3NYM_Reactor_Indicators : SUSPICIOUS OBFUSCATION FILE
{
	meta:
		description = "Ezriz .NET Reactor obfuscator"
		author = "Jonathan Peters"
		id = "8dc07bbd-cbeb-5214-a27a-555a0d396197"
		date = "2024-01-09"
		modified = "2024-01-10"
		reference = "https://github.com/cod3nym/detection-rules/"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/malcat/obfuscators.yar#L103-L119"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		logic_hash = "40a03eb487e2c02a032c4bfb51580dbb764e0a49ceee5ae92c54a5ee3ede9696"
		score = 65
		quality = 80
		tags = "SUSPICIOUS, OBFUSCATION, FILE"
		name = ".NET Reactor"
		category = "obfuscation"
		reliability = 90

	strings:
		$ = { 33 7B 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 2D 00 [9] 00 7D 00 }
		$ = { 3C 50 72 69 76 61 74 65 49 6D 70 6C 65 6D 65 6E 74 61 74 69 6F 6E 44 65 74 61 69 6C 73 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }
		$ = { 3C 4D 6F 64 75 6C 65 3E 7B [8] 2D [4] 2D [4] 2D [4] 2D [12] 7D }

	condition:
		uint16( 0 ) == 0x5a4d and 2 of them
}

