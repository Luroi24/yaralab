rule SIGNATURE_BASE_Powershell_Susp_Parameter_Combo : HIGHVOL FILE
{
	meta:
		description = "Detects PowerShell invocation with suspicious parameters"
		author = "Florian Roth (Nextron Systems)"
		id = "17c707f3-7f51-5772-9874-a96c220960a7"
		date = "2017-03-12"
		modified = "2022-09-15"
		reference = "https://goo.gl/uAic1X"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_powershell_invocation.yar#L2-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "d56d97b4f0506430f21ccb029524111c404c03f8cef25710b96c6c0915fdcf22"
		score = 60
		quality = 31
		tags = "HIGHVOL, FILE"

	strings:
		$sa1 = " -enc " ascii wide nocase
		$sa2 = " -EncodedCommand " ascii wide nocase
		$sa3 = " /enc " ascii wide nocase
		$sa4 = " /EncodedCommand " ascii wide nocase
		$sb1 = " -w hidden " ascii wide nocase
		$sb2 = " -window hidden " ascii wide nocase
		$sb3 = " -windowstyle hidden " ascii wide nocase
		$sb4 = " /w hidden " ascii wide nocase
		$sb5 = " /window hidden " ascii wide nocase
		$sb6 = " /windowstyle hidden " ascii wide nocase
		$sc1 = " -nop " ascii wide nocase
		$sc2 = " -noprofile " ascii wide nocase
		$sc3 = " /nop " ascii wide nocase
		$sc4 = " /noprofile " ascii wide nocase
		$sd1 = " -noni " ascii wide nocase
		$sd2 = " -noninteractive " ascii wide nocase
		$sd3 = " /noni " ascii wide nocase
		$sd4 = " /noninteractive " ascii wide nocase
		$se1 = " -ep bypass " ascii wide nocase
		$se2 = " -exec bypass " ascii wide nocase
		$se3 = " -executionpolicy bypass " ascii wide nocase
		$se4 = " -exec bypass " ascii wide nocase
		$se5 = " /ep bypass " ascii wide nocase
		$se6 = " /exec bypass " ascii wide nocase
		$se7 = " /executionpolicy bypass " ascii wide nocase
		$se8 = " /exec bypass " ascii wide nocase
		$sf1 = " -sta " ascii wide
		$sf2 = " /sta " ascii wide
		$fp1 = "Chocolatey Software" ascii wide
		$fp2 = "VBOX_MSI_INSTALL_PATH" ascii wide
		$fp3 = "\\Local\\Temp\\en-US.ps1" ascii wide
		$fp4 = "Lenovo Vantage - Battery Gauge Helper" wide fullword
		$fp5 = "\\LastPass\\lpwinmetro\\AppxUpgradeUwp.ps1" ascii
		$fp6 = "# use the encoded form to mitigate quoting complications that full scriptblock transfer exposes" ascii
		$fp7 = "Write-AnsibleLog \"INFO - s" ascii
		$fp8 = "\\Packages\\Matrix42\\" ascii
		$fp9 = "echo " ascii
		$fp10 = "install" ascii fullword
		$fp11 = "REM " ascii
		$fp12 = "set /p " ascii
		$fp13 = "rxScan Application" wide
		$fpa1 = "All Rights"
		$fpa2 = "<html"
		$fpa2b = "<HTML"
		$fpa3 = "Copyright"
		$fpa4 = "License"
		$fpa5 = "<?xml"
		$fpa6 = "Help" fullword
		$fpa7 = "COPYRIGHT"

	condition:
		filesize < 3000KB and 4 of ( $s* ) and not 1 of ( $fp* ) and uint32be( 0 ) != 0x456C6646
}

rule SIGNATURE_BASE_SUSP_PDB_Strings_Keylogger_Backdoor : HIGHVOL FILE
{
	meta:
		description = "Detects PDB strings used in backdoors or keyloggers"
		author = "Florian Roth (Nextron Systems)"
		id = "190daadb-0de6-5665-a241-95c374dbda47"
		date = "2018-03-23"
		modified = "2025-03-21"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_suspicious_strings.yar#L109-L130"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "9a842ff8cd8be98a2e37a81706a9c594e8bf1bcc6bd3cedfe4747cd52f6044f5"
		score = 65
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$ = "\\Release\\PrivilegeEscalation"
		$ = "\\Release\\KeyLogger"
		$ = "\\Debug\\PrivilegeEscalation"
		$ = "\\Debug\\KeyLogger"
		$ = "Backdoor\\KeyLogger_"
		$ = "\\ShellCode\\Debug\\"
		$ = "\\ShellCode\\Release\\"
		$ = "\\New Backdoor"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule SIGNATURE_BASE_Coinminer_Strings : SCRIPT HIGHVOL FILE
{
	meta:
		description = "Detects mining pool protocol string in Executable"
		author = "Florian Roth (Nextron Systems)"
		id = "ac045f83-5f32-57a9-8011-99a2658a0e05"
		date = "2018-01-04"
		modified = "2021-10-26"
		reference = "https://minergate.com/faq/what-pool-address"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/pua_cryptocoin_miner.yar#L2-L18"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "2d63bf90560c83ab6c09e0c82b6a6449bca6e7e7d0945d3782c2fa9a726b2ca1"
		score = 60
		quality = 85
		tags = "SCRIPT, HIGHVOL, FILE"
		nodeepdive = 1

	strings:
		$sa1 = "stratum+tcp://" ascii
		$sa2 = "stratum+udp://" ascii
		$sb1 = "\"normalHashing\": true,"

	condition:
		filesize < 3000KB and 1 of them
}

rule SIGNATURE_BASE_Coinhive_Javascript_Monerominer : HIGHVOL FILE
{
	meta:
		description = "Detects CoinHive - JavaScript Crypto Miner"
		author = "Florian Roth (Nextron Systems)"
		id = "4f40c342-fcdc-5c73-a3cf-7b2ed438eaaf"
		date = "2018-01-04"
		modified = "2023-12-05"
		reference = "https://coinhive.com/documentation/miner"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/pua_cryptocoin_miner.yar#L20-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "4146b034a9785f1bb7c60db62db0e478d960f2ac9adb7c5b74b365186578ca47"
		score = 50
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "CoinHive.CONFIG.REQUIRES_AUTH" fullword ascii

	condition:
		filesize < 65KB and 1 of them
}

rule SIGNATURE_BASE_MAL_Neshta_Generic : HIGHVOL FILE
{
	meta:
		description = "Detects Neshta malware"
		author = "Florian Roth (Nextron Systems)"
		id = "9a3b8369-7e19-5c21-9eba-0bb81507696a"
		date = "2018-01-15"
		modified = "2021-04-14"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/mal_netsha.yar#L3-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "acac6f81900c60a0aacea6345a7c03a0b77dd86d5ca7ca3d102668c49595bb6b"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		hash1 = "27c67eb1378c2fd054c6649f92ec8ee9bfcb6f790224036c974f6c883c46f586"
		hash1 = "0283c0f02307adc4ee46c0382df4b5d7b4eb80114fbaf5cb7fe5412f027d165e"
		hash2 = "b7f8233dafab45e3abbbb4f3cc76e6860fae8d5337fb0b750ea20058b56b0efb"
		hash3 = "1954e06fc952a5a0328774aaf07c23970efd16834654793076c061dffb09a7eb"

	strings:
		$x1 = "the best. Fuck off all the rest."
		$x2 = "! Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" fullword ascii
		$s1 = "Neshta" ascii fullword
		$s2 = "Made in Belarus. " ascii fullword
		$op1 = { 85 c0 93 0f 85 62 ff ff ff 5e 5b 89 ec 5d c2 04 }
		$op2 = { e8 e5 f1 ff ff 8b c3 e8 c6 ff ff ff 85 c0 75 0c }
		$op3 = { eb 02 33 db 8b c3 5b c3 53 85 c0 74 15 ff 15 34 }
		$sop1 = { e8 3c 2a ff ff b8 ff ff ff 7f eb 3e 83 7d 0c 00 }
		$sop2 = { 2b c7 50 e8 a4 40 ff ff ff b6 88 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( 1 of ( $x* ) or all of ( $s* ) or 3 of them or pe.imphash ( ) == "9f4693fc0c511135129493f2161d1e86" )
}

rule SIGNATURE_BASE_Gen_Exploit_CVE_2017_10271_Weblogic : HIGHVOL CVE_2017_10271 FILE
{
	meta:
		description = "Exploit for CVE-2017-10271 (Oracle WebLogic)"
		author = "John Lambert @JohnLaTwC"
		id = "e30e316f-1ebb-5c38-ba25-d2a9d0083a03"
		date = "2018-03-21"
		modified = "2023-12-05"
		reference = "https://github.com/c0mmand3rOpSec/CVE-2017-10271, https://www.fireeye.com/blog/threat-research/2018/02/cve-2017-10271-used-to-deliver-cryptominers.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_exploit_cve_2017_10271_weblogic.yar#L1-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "01e4f7b1c9c068f3953fa58749a14ea148d2b038c7266da789e0998eae83e1a7"
		score = 75
		quality = 85
		tags = "HIGHVOL, CVE-2017-10271, FILE"
		hash1 = "376c2bc11d4c366ad4f6fecffc0bea8b195e680b4c52a48d85a8d3f9fab01c95"
		hash2 = "7d5819a2ea62376e24f0dd3cf5466d97bbbf4f5f730eb9302307154b363967ea"
		hash3 = "864e9d8904941fae90ddd10eb03d998f85707dc2faff80cba2e365a64e830e1d/subfile"
		hash4 = "2a69e46094d0fef2b3ffcab73086c16a10b517f58e0c1f743ece4f246889962b"

	strings:
		$s1 = "<soapenv:Header"
		$s2 = "java.beans.XMLDecoder"
		$s3 = "void" fullword
		$s4 = "index="
		$s5 = "/array>"
		$s6 = "\"start\""
		$s7 = "work:WorkContext" nocase

	condition:
		filesize < 10KB and ( uint32( 0 ) == 0x616f733c or uint32( 0 ) == 0x54534f50 ) and all of ( $s* )
}

rule SIGNATURE_BASE_XMRIG_Monero_Miner : HIGHVOL FILE
{
	meta:
		description = "Detects Monero mining software"
		author = "Florian Roth (Nextron Systems)"
		id = "71bf1b9c-c806-5737-83a9-d6013872b11d"
		date = "2018-01-04"
		modified = "2022-11-10"
		reference = "https://github.com/xmrig/xmrig/releases"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/pua_xmrig_monero_miner.yar#L11-L33"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "532e602dfc8e44326e381d0e2a189b60bc4d4f2b310169767b2326e01606a542"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5c13a274adb9590249546495446bb6be5f2a08f9dcd2fc8a2049d9dc471135c0"
		hash2 = "08b55f9b7dafc53dfc43f7f70cdd7048d231767745b76dc4474370fb323d7ae7"
		hash3 = "f3f2703a7959183b010d808521b531559650f6f347a5830e47f8e3831b10bad5"
		hash4 = "0972ea3a41655968f063c91a6dbd31788b20e64ff272b27961d12c681e40b2d2"

	strings:
		$s1 = "'h' hashrate, 'p' pause, 'r' resume" fullword ascii
		$s2 = "--cpu-affinity" ascii
		$s3 = "set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" ascii
		$s4 = "password for mining server" fullword ascii
		$s5 = "XMRig/%s libuv/%s%s" fullword ascii

	condition:
		( uint16( 0 ) == 0x5a4d or uint16( 0 ) == 0x457f ) and filesize < 10MB and 2 of them
}

rule SIGNATURE_BASE_Imphash_Malware_2_TA17_293A : HIGHVOL FILE
{
	meta:
		description = "Detects malware based on Imphash of malware used in TA17-293A"
		author = "Florian Roth (Nextron Systems)"
		id = "5c9f32a3-8c50-5d46-929b-bbe14697540e"
		date = "2017-10-21"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_ta17_293A.yar#L219-L229"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "5f91c07a9cc65c31eb9fd09bdd2752bc285c5a4b118ffe647391f7d187765de4"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 5000KB and pe.imphash ( ) == "a8f69eb2cf9f30ea96961c86b4347282" )
}

rule SIGNATURE_BASE_IMPLANT_4_V3_Alternativerule : HIGHVOL FILE
{
	meta:
		description = "Detects a group of different malware samples"
		author = "Florian Roth (Nextron Systems)"
		id = "47e9028b-7718-5372-8a1a-94c208c29ed4"
		date = "2017-02-12"
		modified = "2023-12-05"
		reference = "US CERT Grizzly Steppe Report"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_grizzlybear_uscert.yar#L788-L803"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "35468f7699b96fcaaaa032eef7dae34ec314e9c652f9f8b2e8ca7343fb5cec50"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		comment = "Alternative rule - not based on the original samples but samples on which the original rule matched"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2244fe9c5d038edcb5406b45361613cf3909c491e47debef35329060b00c985a"

	strings:
		$op1 = { 33 c9 41 ff 13 13 c9 ff 13 72 f8 c3 53 1e 01 00 }
		$op2 = { 21 da 40 00 00 a0 40 00 08 a0 40 00 b0 70 40 00 }

	condition:
		( uint16( 0 ) == 0x5a4d and all of them )
}

rule SIGNATURE_BASE_Malware_Floxif_Mpsvc_Dll : HIGHVOL FILE
{
	meta:
		description = "Malware - Floxif"
		author = "Florian Roth (Nextron Systems)"
		id = "37af366a-24b2-5402-b0b5-6e2c80f8c903"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_floxif.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "e51258558dfd9a2c65589100a224492f4582067484c99d405b2d432a48cc6ed8"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "1e654ee1c4736f4ccb8b5b7aa604782cfb584068df4d9e006de8009e60ab5a14"

	strings:
		$op1 = { 04 80 7a 03 01 75 04 8d 42 04 c3 8d 42 04 53 8b }
		$op2 = { 88 19 74 03 41 eb ea c6 42 03 01 5b c3 8b 4c 24 }
		$op3 = { ff 03 8d 00 f9 ff ff 88 01 eb a1 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}

rule SIGNATURE_BASE_Irontiger_Aspxspy : HIGHVOL
{
	meta:
		description = "ASPXSpy detection. It might be used by other fraudsters"
		author = "Cyber Safety Solutions, Trend Micro"
		id = "3010fcb9-0dbf-59ef-90ce-01d922a95f2d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://goo.gl/T5fSJC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_irontiger_trendmicro.yar#L1-L13"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "6b5830d3fd6aa346b27788cd4abd581b4724fecc4e880b14dd7b1dd27ef1eea3"
		score = 75
		quality = 85
		tags = "HIGHVOL"

	strings:
		$str2 = "IIS Spy" wide ascii
		$str3 = "protected void DGCoW(object sender,EventArgs e)" wide ascii

	condition:
		any of ( $str* )
}

rule SIGNATURE_BASE_Backdoor_Redosdru_Jun17 : HIGHVOL FILE
{
	meta:
		description = "Detects malware Redosdru - file systemHome.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ea038142-6903-5d08-ac89-70c1bbef716c"
		date = "2017-06-04"
		modified = "2023-12-05"
		reference = "https://goo.gl/OOB3mH"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_eternalblue_non_wannacry.yar#L12-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "99218c4decf98f02eb75c3c41a56f857a07779c68d30c4d16ca605052c4f9c3e"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4f49e17b457ef202ab0be905691ef2b2d2b0a086a7caddd1e70dd45e5ed3b309"

	strings:
		$x1 = "%s\\%d.gho" fullword ascii
		$x2 = "%s\\nt%s.dll" fullword ascii
		$x3 = "baijinUPdate" fullword ascii
		$s1 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii
		$s2 = "serviceone" fullword ascii
		$s3 = "\x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#p \x1f#f \x1f#" fullword ascii
		$s4 = "servicetwo" fullword ascii
		$s5 = "UpdateCrc" fullword ascii
		$s6 = "\x1f#[ \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#x \x1f#" fullword ascii
		$s7 = "nwsaPAgEnT" fullword ascii
		$s8 = "%-24s %-15s 0x%x(%d) " fullword ascii

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 700KB and 1 of ( $x* ) or 4 of them )
}

rule SIGNATURE_BASE_MAL_XMR_Miner_May19_1 : HIGHVOL FILE
{
	meta:
		description = "Detects Monero Crypto Coin Miner"
		author = "Florian Roth (Nextron Systems)"
		id = "233d1d47-de67-55a9-ae7e-46b5dd34e6ce"
		date = "2019-05-31"
		modified = "2023-12-05"
		reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/crime_nansh0u.yar#L15-L36"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "85a65fd2355850b7f5261ad41091e181562938356ba3dae7d867f7ac8922a16e"
		score = 85
		quality = 85
		tags = "HIGHVOL, FILE"
		hash1 = "d6df423efb576f167bc28b3c08d10c397007ba323a0de92d1e504a3f490752fc"

	strings:
		$x1 = "donate.ssl.xmrig.com" fullword ascii
		$x2 = "* COMMANDS     'h' hashrate, 'p' pause, 'r' resume" fullword ascii
		$s1 = "[%s] login error code: %d" fullword ascii
		$s2 = "\\\\?\\pipe\\uv\\%p-%lu" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 14000KB and ( pe.imphash ( ) == "25d9618d1e16608cd5d14d8ad6e1f98e" or 1 of ( $x* ) or 2 of them )
}

rule SIGNATURE_BASE_Processinjector_Gen : HIGHVOL FILE
{
	meta:
		description = "Detects a process injection utility that can be used ofr good and bad purposes"
		author = "Florian Roth (Nextron Systems)"
		id = "9b0b6ac7-8432-5f93-b389-c2356ec75113"
		date = "2018-04-23"
		modified = "2025-04-14"
		reference = "https://github.com/cuckoosandbox/monitor/blob/master/bin/inject.c"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/thor-hacktools.yar#L4198-L4219"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "90d200e79c97911b105e592549bc2c04fb09ce841413c30117d421b45bb9988c"
		score = 60
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "456c1c25313ce2e2eedf24fdcd4d37048bcfff193f6848053cbb3b5e82cd527d"

	strings:
		$x1 = "Error injecting remote thread in process:" fullword ascii
		$s5 = "[-] Error getting access to process: %ld!" fullword ascii
		$s6 = "--process-name <name>  Process name to inject" fullword ascii
		$s12 = "No injection target has been provided!" fullword ascii
		$s17 = "[-] An app path is required when not injecting!" fullword ascii

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and ( pe.imphash ( ) == "d27e0fa013d7ae41be12aaf221e41f9b" or 1 of them ) or 3 of them
}

rule SIGNATURE_BASE_Gen_Base64_EXE : HIGHVOL FILE
{
	meta:
		description = "Detects Base64 encoded Executable in Executable"
		author = "Florian Roth (Nextron Systems)"
		id = "ef919a63-9a29-5624-a084-b92e3578e3a6"
		date = "2017-04-21"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/general_cloaking.yar#L71-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "6fe18ee727a836c0baaac4dbbffdb9f50065f56a4c6eeee7e54792a8a66229de"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" wide ascii
		$s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" wide ascii
		$s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" wide ascii
		$s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" wide ascii
		$s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii
		$fp1 = "BAM Management class library"

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and 1 of ( $s* ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_Suspicious_Powershell_Webdownload_1 : HIGHVOL FILE
{
	meta:
		description = "Detects suspicious PowerShell code that downloads from web sites"
		author = "Florian Roth (Nextron Systems)"
		id = "a763fb82-c840-531b-b631-f282bf035020"
		date = "2017-02-22"
		modified = "2024-04-03"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_powershell_susp.yar#L52-L91"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "56ad9c71c34956e94325452d829627a30b1499552725232a07100f05a050ef1b"
		score = 60
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		nodeepdive = 1

	strings:
		$s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
		$s2 = "System.Net.WebClient).DownloadString('http" ascii nocase
		$s3 = "system.net.webclient).downloadfile('http" ascii nocase
		$s4 = "system.net.webclient).downloadfile(\"http" ascii nocase
		$s5 = "GetString([Convert]::FromBase64String(" ascii nocase
		$fp1 = "NuGet.exe" ascii fullword
		$fp2 = "chocolatey.org" ascii
		$fp3 = " GET /"
		$fp4 = " POST /"
		$fp5 = ".DownloadFile('https://aka.ms/installazurecliwindows', 'AzureCLI.msi')" ascii
		$fp6 = " 404 "
		$fp7 = "# RemoteSSHConfigurationScript" ascii
		$fp8 = "<helpItems" ascii fullword
		$fp9 = "DownloadFile(\"https://codecov.io/bash" ascii
		$fp10 = "DownloadFile('https://get.golang.org/installer.exe" ascii
		$fpg1 = "All Rights"
		$fpg2 = "<html"
		$fpg3 = "<HTML"
		$fpg4 = "Copyright"
		$fpg5 = "License"
		$fpg6 = "<?xml"
		$fpg7 = "Help" fullword
		$fpg8 = "COPYRIGHT" fullword

	condition:
		1 of ( $s* ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_MAL_Malware_Imphash_Mar23_1 : HIGHVOL FILE
{
	meta:
		description = "Detects malware by known bad imphash or rich_pe_header_hash"
		author = "Arnim Rupp"
		id = "fb398c26-e9ac-55f9-b605-6b763021e96a"
		date = "2023-03-20"
		modified = "2023-03-22"
		reference = "https://yaraify.abuse.ch/statistics/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_imphash_detection.yar#L4-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "167dde6bd578cbfcc587d5853e7fc2904cda10e737ca74b31df52ba24db6e7bc"
		hash = "0a25a78c6b9df52e55455f5d52bcb3816460001cae3307b05e76ac70193b0636"
		hash = "d87a35decd0b81382e0c98f83c7f4bf25a2b25baac90c9dcff5b5a147e33bcc8"
		hash = "5783bf969c36f13f4365f4cae3ec4ee5d95694ff181aba74a33f4959f1f19e8b"
		hash = "4ca925b0feec851d787e7ee42d263f4c08b0f73f496049bdb5d967728ff91073"
		hash = "9c2d2fa9c32fdff1828854e8cc39160dae73a4f90fb89b82ef6d853b63035663"
		hash = "2c53d58f30b2ee1a2a7746e20f136c34d25d0214261783fc67e119329d457c2a"
		hash = "5e83747015b0589b4f04b0db981794adf53274076c1b4acf717e3ff45eca0249"
		hash = "ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247"
		hash = "82fb1ba998dfee806a513f125bb64c316989c36c805575914186a6b45da3b132"
		hash = "cb41d2520995abd9ba8ccd42e53d496a66da392007ea6aebd4cbc43f71ad461a"
		hash = "c7bd758506b72ee6db1cc2557baf745bf9e402127d8e49266cc91c90f3cf3ed5"
		hash = "e6e0d60f65a4ea6895ff97df340f6d90942bbfa402c01bf443ff5b4641ff849f"
		hash = "e8ddef9fa689e98ba2d48260aea3eb8fa41922ed718b7b9135df6426b3ddf126"
		hash = "ad57d77aba6f1bf82e0affe4c0ae95964be45fb3b7c2d6a0e08728e425ecd301"
		hash = "483df98eb489899bc89c6a0662ca8166c9b77af2f6bedebd17e61a69211843d9"
		hash = "a65ed85851d8751e6fe6a27ece7b3879b90866a10f272d8af46fb394b46b90a9"
		hash = "09081e04f3228d6ef2efc1108850958ed86026e4dfda199852046481f4711565"
		hash = "1b2c9054f44f7d08cffe7e2d9127dbd96206ab2c15b63ebf6120184950336ae1"
		hash = "257887d1c84eb15abb2c3c0d7eb9b753ca961d905f4979a10a094d0737d97138"
		hash = "1cbad8b58dbd1176e492e11f16954c3c254b5169dde52b5ad6d0d3c51930abf8"
		hash = "a9897fd2d5401071a8219b05a3e9b74b64ad67ab75044b3e41818e6305a8d7b9"
		hash = "aeac45fbc5d2a59c9669b9664400aeaf6699d76a57126d2f437833a3437a693e"
		hash = "7b4c4d4676fab6c009a40d370e6cb53ea4fd73b09c23426fbaccc66d652f2a00"
		hash = "b07f6873726276842686a6a6845b361068c3f5ce086811db05c1dc2250009cd0"
		hash = "d1b3afebcacf9dd87034f83d209b42b0d79e66e08c0a897942fbe5fbd6704a0e"
		hash = "074d52be060751cf213f6d0ead8e9ab1e63f055ae79b5fcbe4dd18469deea12b"
		hash = "84d1fdef484fa9f637ae3d6820c996f6c5cf455470e8717ad348a3d80d2fb8e0"
		hash = "437da123e80cfd10be5f08123cd63cfc0dc561e17b0bef861634d60c8a134eda"
		hash = "f76c36eb22777473b88c6a5fc150fd9d6b5fac5b2db093f0ccd101614c46c7e7"
		hash = "5498b7995669877a410e1c2b68575ca94e79014075ef5f89f0f1840c70ebf942"
		hash = "af4e633acfba903e7c92342b114c4af4e694c5cfaea3d9ea468a4d322b60aa85"
		hash = "d7d870f5afab8d4afa083ea7d7ce6407f88b0f08ca166df1a1d9bdc1a46a41b3"
		hash = "974209d88747fbba77069bb9afa9e8c09ee37ae233d94c82999d88dfcd297117"
		hash = "f2d99e7d3c59adf52afe0302b298c7d8ea023e9338c2870f74f11eaa0a332fc4"
		hash = "b32c93be9320146fc614fafd5e6f1bb8468be83628118a67eb01c878f941ee5d"
		hash = "bbd99acc750e6457e89acbc5da8b2a63b4ef01d4597d160e9cde5dc8bd04cf74"
		hash = "dbff5ca3d1e18902317ab9c50be4e172640a8141e09ec13dcca986f2ec1dc395"
		hash = "3ee1741a649f0b97bbeb05b6f9df97afda22c82e1e870177d8bdd34141ef163c"
		hash = "222096fc800c8ea2b0e530302306898b691858324dbe5b8357f90407e9665b85"
		hash = "b9995d1987c4e8b6fb30d255948322cfad9cc212c7f8f4c5db3ac80e23071533"
		hash = "a6a92ea0f27da1e678c15beb263647de43f68608afe82d6847450f16a11fe6c0"
		hash = "866e3ea86671a62b677214f07890ddf7e8153bec56455ad083c800e6ab51be37"
		logic_hash = "dcb4d9a1ca83bbd26178895f20f9ab443f48f42aa3ad3df042c763c24ce8c047"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"

	strings:
		$fp1 = "Win32 Cabinet Self-Extractor" wide
		$fp2 = "EXTRACTOPT" ascii fullword

	condition:
		uint16( 0 ) == 0x5A4D and ( pe.imphash ( ) == "9ee34731129f4801db97fd66adbfeaa0" or pe.imphash ( ) == "f9e8597c55008e10a8cdc8a0764d5341" or pe.imphash ( ) == "0a76016a514d8ed3124268734a31e2d2" or pe.imphash ( ) == "d3cbd6e8f81da85f6bf0529e69de9251" or pe.imphash ( ) == "d8b32e731e5438c6329455786e51ab4b" or pe.imphash ( ) == "cdf5bbb8693f29ef22aef04d2a161dd7" or pe.imphash ( ) == "890e522b31701e079a367b89393329e6" or pe.imphash ( ) == "bf5a4aa99e5b160f8521cadd6bfe73b8" or pe.imphash ( ) == "646167cce332c1c252cdcb1839e0cf48" or pe.imphash ( ) == "9f4693fc0c511135129493f2161d1e86" or pe.imphash ( ) == "b4c6fff030479aa3b12625be67bf4914" ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_SUSP_Imphash_Mar23_2 : HIGHVOL FILE
{
	meta:
		description = "Detects imphash often found in malware samples (Zero hits with with search for 'imphash:x p:0' on Virustotal)"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "b739d540-5d9f-53b3-9e42-a514dc972e8d"
		date = "2023-03-23"
		modified = "2023-11-25"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_imphash_detection.yar#L194-L295"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		hash = "12bf2795f4a140adbaa0af6ad4b2508d398d8ba69e9dadb155f800b10f7458c4"
		hash = "14ec56489fbcc3c7f1ef9a4d4a80ff302a5e233cdc4429a29c635a88fb1278d6"
		hash = "13731912823d6ce01c28a8d7d7f961505f461620bb35adbb409d4954ba1f4b8e"
		hash = "15e59cc5d7b83e63d40dbfd8406701cb4decd31353f68fda47238d073c87e4ea"
		hash = "13e5bb40be20b1a0bc28081ce7798f339c28c9652cb37b538c29872dfd0cd51d"
		hash = "16f963afdb30b38ba4b8b98ce56a37626e9fd87de9eba5f9903d2ba7f8a77788"
		hash = "168f22d02304ce66be88d2370c8fa7c7d9aa2ccf80f8e376edfeabfc9b96c73d"
		hash = "9e7701450dbcbd35083e34df935bd77a95735c4b441e0fc8eacd543a621f2fa5"
		hash = "51205c100702b21cce600692d69f3b108f49228e53f36678dd8b39434406526b"
		hash = "c9b48e8b0e7c6fa75886554659bc0529e454d84b29daa07bd4323aca9a33f607"
		hash = "ba5c06703bd3c093afa89e45d86aaf6c151fbaef44ebf3b65c97f3b376a88c72"
		hash = "7281afc138e8e898aee16d415cd02a29dc5dedda5b11c23934aac0ebd208373b"
		hash = "10a091b2468a8286f7b1a580d8923aef48856b43014e849035f05c4dbdc0a413"
		hash = "56c04e76427bd982be83799d0a435732193d7bf5a70cdeba5eb63eaf0d4ebb77"
		hash = "0aa8b7eddc4792a82f247702442c04e50173bd7712a4b596545916480942853b"
		hash = "627f043ad875c182682149653363b7f856dd618d169821b18df7bc9cdf6269d8"
		hash = "e1df460fd99c4f901859f3a8ec23b041ba9f4b79897dec349a96d6a27fb3e335"
		hash = "f10ecbd8031ce85b782c59682ff32301a65e0975687977688771f1057fb063d1"
		hash = "1bc7b8932b5b077b359c79e7ca664938b7a487a4e7e6b99d6647d6803bc677c5"
		hash = "01f81029a5e93cbfecfbc81cbd4a2ffd1bb1b6159e2a144a21e58caf8dab9661"
		hash = "cd33a71f71e2971667bacb0da71f2d36073777993b9581ec90bbf042162c3530"
		hash = "4aab991149cb2dc8c0c0a323af3acbbd73d6a22177910ef3af92b05ae7c9ae7b"
		hash = "df05fa3983c9e623388231d366dba4e435575ca53421d3f0bcb0fb346dd971d4"
		hash = "14de3584fe7108386f7637c2bd343f30341c0fa2102d52bb35ee772b5b7672f0"
		hash = "c4d9ad5cffd9aa13dfe3acbf0905810e28ff96d231541d7e209327ca5b0b24fe"
		hash = "5e0bed2269dc34c6cc2db30b0a53282e6debb85b3c90a857d1be4cfd06312211"
		hash = "3aa13e72382a2d7da592273b8c18a42106b65db528e16b6066646812e81555c4"
		hash = "244c4a930e3644ffb96bf3ab33e8c8c0f94ed9fe6a8b2fc45fc8e9b6471ef3a8"
		hash = "f00848b8edeeb5a668bf7e89e3f33f438b2f5d5cf130596a8ed2531e21be6d81"
		hash = "5b9348c24ff604e78d70464654e645b90dc695c7e0415959c443fe29cebc3c4e"
		logic_hash = "c6482cbc01a880ffd3056d28a2fde8f87402b1f85d36075c1f0b50788d469ca3"
		score = 65
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"

	condition:
		uint16( 0 ) == 0x5A4D and ( pe.imphash ( ) == "e4290fa6afc89d56616f34ebbd0b1f2c" or pe.imphash ( ) == "8abecba2211e61763c4c9ffcaa13369e" or pe.imphash ( ) == "a64e048b98d051ae6e6b6334f77c95d3" or pe.imphash ( ) == "359d89624a26d1e756c3e9d6782d6eb0" or pe.imphash ( ) == "c2a87fabf96470db507b2e6b43bd92eb" or pe.imphash ( ) == "62ec3dce1eba1b68f6a4511bb09f8c2c" or pe.imphash ( ) == "5662cfcdfd9da29cb429e7528d5af81e" or pe.imphash ( ) == "406c785a6e2c6970c1e8ed62877e197b" or pe.imphash ( ) == "dbf687d6aa2a6cafe4349f7b0821a792" or pe.imphash ( ) == "6dca3e9fb3928bbdb54dbce669943ec8" or pe.imphash ( ) == "f1a539a5b71ad53ac586f053145f08ec" or pe.imphash ( ) == "3a2003ea545fe942681da9e7683ebb58" or pe.imphash ( ) == "a8286b574ff850cd002ea6282d15aa40" or pe.imphash ( ) == "3c8577ca4bab2f95cc6fc73ef1895288" or pe.imphash ( ) == "84706849fa809feaa385711a628be029" or pe.imphash ( ) == "ba23a556ac1d6444f7f76feafd6c8867" or pe.imphash ( ) == "95e6f8741083e0c7d9a63d45e2472360" or pe.imphash ( ) == "774d797db707398fd2ef1979d02634d5" or pe.imphash ( ) == "8c16c795b57934183422be5f6df7d891" or pe.imphash ( ) == "98f67c550a7da65513e63ffd998f6b2e" or pe.imphash ( ) == "e836076a09dba03e4d6faa46dda0fefc" or pe.imphash ( ) == "ff63dc9c65eb25911a9bc535c8f06ad0" or pe.imphash ( ) == "08b67a9663d3a8c9505f3b2561bbdd1c" or pe.imphash ( ) == "135e92fc9902f3140f2e5a51458efdf0" or pe.imphash ( ) == "4753904c40d638a1bc745c65b88291d5" or pe.imphash ( ) == "0f44bf2b3b0b8d5ecae5689ff1d0e90d" or pe.imphash ( ) == "c4c9ecfc26ca516a80b8f6f5b2bdb7e6" or pe.imphash ( ) == "46ad3d954e527f769e37017b3e128039" or pe.imphash ( ) == "802dcac7aab948c19738ba3df9f356d9" or pe.imphash ( ) == "b36a21279375c40e6f4c1ea347f906de" or pe.imphash ( ) == "77a185e903c5527243ef219b003bfd38" or pe.imphash ( ) == "12a30b523ac71a3cbe9145c89400dd7f" or pe.imphash ( ) == "cc40fefa3af5cd00cc28dbd874038a4d" or pe.imphash ( ) == "3d8c26f4cb1782a87c3bb42796fb6b85" or pe.imphash ( ) == "2f4ddcfebbcad3bacadc879747151f6f" or pe.imphash ( ) == "76812f441b0ed9d3cc0748af25d689a3" or pe.imphash ( ) == "9a06f0024c1694774ae97311608bab5b" or pe.imphash ( ) == "481f47bbb2c9c21e108d65f52b04c448" or pe.imphash ( ) == "286870a926664a5129b8b68ed0d4a8eb" or pe.imphash ( ) == "a0db151d55761167d93eba72d3d94b32" or pe.imphash ( ) == "663243fe4d94e1304b265ce4011cd01b" or pe.imphash ( ) == "f24e64014af9015dc25262e5076fe61f" or pe.imphash ( ) == "b7d08302c927428e16a2ad8d18b9d2b7" or pe.imphash ( ) == "352063077f27a851dc2b08e15f08105e" or pe.imphash ( ) == "b0b97d1a91a2730b3daa8bbb2e86b402" or pe.imphash ( ) == "bc96f1c981700752dc2cf9553da99eb6" or pe.imphash ( ) == "f68ddef5f29b66bbd543e947c8743bb0" or pe.imphash ( ) == "6dfbc160505aa2f7205766eaa6fe72a1" or pe.imphash ( ) == "a202429ffe8d8c8b722572cffd5681a7" or pe.imphash ( ) == "342a3708d93b6b819b7b1a768201a747" or pe.imphash ( ) == "cdc00badc7162acde9bb032e793ac137" or pe.imphash ( ) == "be19e18d6a8b41631d40059031a928bb" or pe.imphash ( ) == "0c54f96a844b02689687407de9b6663e" or pe.imphash ( ) == "fa5f28e70130a452b7c0a51db5544ef9" or pe.imphash ( ) == "2e5708ae5fed0403e8117c645fb23e5b" or pe.imphash ( ) == "8d92fa1956a6a631c642190121740197" or pe.imphash ( ) == "dc73a9bd8de0fd640549c85ac4089b87" )
}

rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_PC_Legacy_Dll : HIGHVOL FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "254ff1f7-52ee-57fa-be02-2904e132e25c"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_eqgrp_apr17.yar#L3129-L3144"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "923a595737bc83fe05d0ca7301c70e1cb03cecf97dfa99f5967b77b892a9a533"
		score = 75
		quality = 85
		tags = "HIGHVOL, FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0cbc5cc2e24f25cb645fb57d6088bcfb893f9eb9f27f8851503a1b33378ff22d"

	strings:
		$op1 = { 45 f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 }
		$op2 = { 49 c6 45 e1 73 c6 45 e2 57 c6 45 e3 }
		$op3 = { 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 6f c6 45 ea }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}

