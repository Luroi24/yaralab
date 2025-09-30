rule DITEKSHEN_INDICATOR_RTF_EXPLOIT_CVE_2017_8759_1 : CVE_2017_8759 FILE
{
	meta:
		description = "detects CVE-2017-8759 weaponized RTF documents."
		author = "ditekSHen"
		id = "8f873145-b909-5185-9f85-07c820d1f38e"
		date = "2024-09-06"
		modified = "2024-09-06"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_office.yar#L215-L238"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "595dc0153a2349fbd4f92dd544a3dfd05715059dd639653e7c7e6ac80624360e"
		score = 75
		quality = 75
		tags = "CVE-2017-8759, FILE"

	strings:
		$clsid1 = { 00 03 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$clsid2 = { 00 03 00 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
		$clsid3 = "0003000000000000c000000000000046" ascii nocase
		$clsid4 = "4f4c45324c696e6b" ascii nocase
		$clsid5 = "OLE2Link" ascii nocase
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = "d0cf11e0a1b11ae1" ascii nocase
		$ole3 = "64306366313165306131623131616531" ascii
		$ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31"
		$s1 = "wsdl=http" wide
		$s2 = "METAFILEPICT" ascii
		$s3 = "INCLUDEPICTURE \"http" ascii
		$s4 = "!This program cannot be run in DOS mode" ascii

	condition:
		uint32( 0 ) == 0x74725c7b and 1 of ( $clsid* ) and 1 of ( $ole* ) and 2 of ( $s* )
}

rule DITEKSHEN_INDICATOR_RTF_EXPLOIT_CVE_2017_8759_2 : CVE_2017_8759 FILE
{
	meta:
		description = "detects CVE-2017-8759 weaponized RTF documents."
		author = "ditekSHen"
		id = "92c8f45e-3792-51b3-bda4-7e9eae0e9a80"
		date = "2024-09-06"
		modified = "2024-09-06"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_office.yar#L240-L268"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "15c9a5cfce5d1a797bab049352d8506b8bc112cabe2f510019f5d203690419e8"
		score = 75
		quality = 75
		tags = "CVE-2017-8759, FILE"

	strings:
		$clsid1 = { 88 d9 6a 0c f1 92 11 d4 a6 5f 00 40 96 32 51 e5 }
		$clsid2 = "88d96a0cf19211d4a65f0040963251e5" ascii nocase
		$clsid3 = "4d73786d6c322e534158584d4c5265616465722e" ascii nocase
		$clsid4 = "Msxml2.SAXXMLReader." ascii nocase
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = "d0cf11e0a1b11ae1" ascii nocase
		$ole3 = "64306366313165306131623131616531" ascii
		$ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31"
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\objclass htmlfile" ascii
		$soap1 = "c7b0abec197fd211978e0000f8757e" ascii nocase

	condition:
		uint32( 0 ) == 0x74725c7b and 1 of ( $clsid* ) and 1 of ( $ole* ) and ( 2 of ( $obj* ) or 1 of ( $soap* ) )
}

rule DITEKSHEN_INDICATOR_RTF_Exploit_Scripting : CVE_2017_8759 CVE_2017_8570 FILE
{
	meta:
		description = "detects CVE-2017-8759 or CVE-2017-8570 weaponized RTF documents."
		author = "ditekSHen"
		id = "e8fd1231-3ef5-5b0b-987c-f55337804da3"
		date = "2024-09-06"
		modified = "2024-09-06"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_office.yar#L270-L302"
		license_url = "https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/LICENSE.txt"
		logic_hash = "a1f4c833f0132dcbe2b3677d6ac0f3597c152702515375d60d4332c21183bd76"
		score = 75
		quality = 75
		tags = "CVE-2017-8759, CVE-2017-8570, FILE"

	strings:
		$clsid1 = { 00 03 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$clsid2 = "0003000000000000c000000000000046" ascii nocase
		$clsid3 = "4f4c45324c696e6b" ascii nocase
		$clsid4 = "OLE2Link" ascii nocase
		$ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
		$ole2 = "d0cf11e0a1b11ae1" ascii nocase
		$ole3 = "64306366313165306131623131616531" ascii
		$ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31"
		$ole5 = { 64 30 63 66 [0-2] 31 31 65 30 61 31 62 31 31 61 65 31 }
		$ole6 = "D0cf11E" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii
		$obj8 = "\\objclass htmlfile" ascii
		$sct1 = { 33 (43|63) (3533|3733) (3433|3633) (3532|3732) (3439|3639)( 3530|3730) (3534|3734) (3443|3643) (3435|3635) (3534|3734) }
		$sct2 = { (3737|3537) (3733|3533) (3633|3433) (3732|3532) (3639|3439) (3730|3530) (3734|3534) (3245|3265) (3733|3533) (3638|3438) (3635|3435) (3643|3443) (3643|3443) }

	condition:
		uint32( 0 ) == 0x74725c7b and 1 of ( $clsid* ) and 1 of ( $ole* ) and 1 of ( $obj* ) and 1 of ( $sct* )
}

rule SIGNATURE_BASE_CVE_2017_8759_Mal_HTA : CVE_2017_8759 FILE
{
	meta:
		description = "Detects malicious files related to CVE-2017-8759 - file cmd.hta"
		author = "Florian Roth (Nextron Systems)"
		id = "e53b5149-fc94-5da5-8e35-7f09a9cd79fd"
		date = "2017-09-14"
		modified = "2023-12-05"
		reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2017_8759.yar#L11-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "f98578104e411fcf75a46f8a0bc3e561c94d0ca4ad7c1aae2595d03a29efd74e"
		score = 75
		quality = 85
		tags = "CVE-2017-8759, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fee2ab286eb542c08fdfef29fabf7796a0a91083a0ee29ebae219168528294b5"

	strings:
		$x1 = "Error = Process.Create(\"powershell -nop cmd.exe /c" fullword ascii

	condition:
		( uint16( 0 ) == 0x683c and filesize < 1KB and all of them )
}

rule SIGNATURE_BASE_CVE_2017_8759_Mal_Doc : CVE_2017_8759 FILE
{
	meta:
		description = "Detects malicious files related to CVE-2017-8759 - file Doc1.doc"
		author = "Florian Roth (Nextron Systems)"
		id = "48587c13-7661-5987-8331-732115f7823b"
		date = "2017-09-14"
		modified = "2023-11-21"
		reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2017_8759.yar#L26-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "0c81feebef463fee41661ca951a39ee789db5d36acc8262ddb391609d8680108"
		score = 75
		quality = 85
		tags = "CVE-2017-8759, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "6314c5696af4c4b24c3a92b0e92a064aaf04fd56673e830f4d339b8805cc9635"

	strings:
		$s1 = "soap:wsdl=http://" ascii wide
		$s2 = "soap:wsdl=https://" ascii wide
		$s3 = "soap:wsdl=http%3" ascii wide
		$s4 = "soap:wsdl=https%3" ascii wide
		$c1 = "Project.ThisDocument.AutoOpen" fullword wide

	condition:
		uint16( 0 ) == 0xcfd0 and filesize < 500KB and ( 1 of ( $s* ) and $c1 )
}

rule SIGNATURE_BASE_CVE_2017_8759_SOAP_Excel : CVE_2017_8759 FILE
{
	meta:
		description = "Detects malicious files related to CVE-2017-8759"
		author = "Florian Roth (Nextron Systems)"
		id = "940ec910-49a4-5271-97e4-8536db271b80"
		date = "2017-09-15"
		modified = "2023-12-05"
		reference = "https://twitter.com/buffaloverflow/status/908455053345869825"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2017_8759.yar#L63-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "adea595b251796e93cdc54cc59198d88a68e28d42899c90721f63f6813df24fe"
		score = 60
		quality = 83
		tags = "CVE-2017-8759, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "|'soap:wsdl=" ascii wide nocase

	condition:
		( filesize < 300KB and 1 of them )
}

rule SIGNATURE_BASE_CVE_2017_8759_SOAP_Txt : CVE_2017_8759 FILE
{
	meta:
		description = "Detects malicious file in releation with CVE-2017-8759 - file exploit.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "36474420-4fa9-5264-a46b-bb2434624710"
		date = "2017-09-14"
		modified = "2023-12-05"
		reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2017_8759.yar#L78-L92"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "184179006ed2ac2ad76e09c53196805fcb1b7380dab1d5740b4469a89d6b0b32"
		score = 75
		quality = 60
		tags = "CVE-2017-8759, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "840ad14e29144be06722aff4cc04b377364eeed0a82b49cc30712823838e2444"

	strings:
		$s1 = /<soap:address location="http[s]?:\/\/[^"]{8,140}.hta"/ ascii wide
		$s2 = /<soap:address location="http[s]?:\/\/[^"]{8,140}mshta.exe"/ ascii wide

	condition:
		( filesize < 200KB and 1 of them )
}

rule SIGNATURE_BASE_CVE_2017_8759_WSDL_In_RTF : CVE_2017_8759 FILE
{
	meta:
		description = "Detects malicious RTF file related CVE-2017-8759"
		author = "Security Doggo @xdxdxdxdoa"
		id = "daaa5489-af96-5a69-b2dd-81406c0a1edc"
		date = "2017-09-15"
		modified = "2023-12-05"
		reference = "https://twitter.com/xdxdxdxdoa/status/908665278199996416"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_cve_2017_8759.yar#L94-L110"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "47adc7adfc55239792aef818648546adb1627e74690de0d811100cc49aab8c2f"
		score = 75
		quality = 85
		tags = "CVE-2017-8759, FILE"

	strings:
		$doc = "d0cf11e0a1b11ae1"
		$obj = "\\objupdate"
		$wsdl = "7700730064006c003d00" nocase
		$http1 = "68007400740070003a002f002f00" nocase
		$http2 = "680074007400700073003a002f002f00" nocase
		$http3 = "6600740070003a002f002f00" nocase

	condition:
		uint32be( 0 ) == 0x7B5C7274 and $obj and $doc and $wsdl and 1 of ( $http* )
}

