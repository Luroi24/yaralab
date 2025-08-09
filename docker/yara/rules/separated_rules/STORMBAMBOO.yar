rule VOLEXITY_Apt_Malware_Macos_Gimmick : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detects the macOS port of the GIMMICK malware."
		author = "threatintel@volexity.com"
		id = "3d485788-4aab-511b-a49e-5dc09d1950a9"
		date = "2021-10-18"
		modified = "2024-08-02"
		reference = "https://www.volexity.com/blog/2022/03/22/storm-cloud-on-the-horizon-gimmick-malware-strikes-at-macos/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-03-22 GIMMICK/indicators/yara.yar#L1-L59"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "00fba9df2212874a45d44b3d098a7b76c97fcd53ff083c76b784d2b510a4a467"
		score = 75
		quality = 78
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
		os = "darwin"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6022
		version = 8

	strings:
		$s1 = "http://cgi1.apnic.net/cgi-bin/my-ip.php --connect-timeout 10 -m 20" wide ascii
		$json1 = "base_json" ascii wide
		$json2 = "down_json" ascii wide
		$json3 = "upload_json" ascii wide
		$json4 = "termin_json" ascii wide
		$json5 = "request_json" ascii wide
		$json6 = "online_json" ascii wide
		$json7 = "work_json" ascii wide
		$msg1 = "bash_pid: %d, FDS_CHILD: %d, FDS_PARENT: %d" ascii wide
		$msg2 = "pid %d is dead" ascii wide
		$msg3 = "exit with code %d" ascii wide
		$msg4 = "recv signal %d" ascii wide
		$cmd1 = "ReadCmdQueue" ascii wide
		$cmd2 = "read_cmd_server_timer" ascii wide
		$cmd3 = "enableProxys" ascii wide
		$cmd4 = "result_block" ascii wide
		$cmd5 = "createDirLock" ascii wide
		$cmd6 = "proxyLock" ascii wide
		$cmd7 = "createDirTmpItem" ascii wide
		$cmd8 = "dowfileLock" ascii wide
		$cmd9 = "downFileTmpItem" ascii wide
		$cmd10 = "filePathTmpItem" ascii wide
		$cmd11 = "uploadItems" ascii wide
		$cmd12 = "downItems" ascii wide
		$cmd13 = "failUploadItems" ascii wide
		$cmd14 = "failDownItems" ascii wide
		$cmd15 = "downloadCmds" ascii wide
		$cmd16 = "uploadFiles" ascii wide
		$cmd17 = "bash callback...." ascii wide

	condition:
		$s1 or 5 of ( $json* ) or 3 of ( $msg* ) or 9 of ( $cmd* )
}

rule VOLEXITY_Apt_Malware_Win_Gimmick_Dotnet_Base : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detects the base version of GIMMICK written in .NET."
		author = "threatintel@volexity.com"
		id = "be42d85f-3143-51d3-b148-95d0ae666771"
		date = "2020-03-16"
		modified = "2024-08-19"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-03-22 GIMMICK/indicators/yara.yar#L60-L86"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "39a38ea189d5e840f9334cb7ec8f390444139b39c6f426906a8845f9a1ada9f7"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "b554bfe4c2da7d0ac42d1b4f28f4aae854331fd6d2b3af22af961f6919740234"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6628
		version = 3

	strings:
		$other1 = "srcStr is null" wide
		$other2 = "srcBs is null " wide
		$other3 = "Key cannot be null" wide
		$other4 = "Faild to get target constructor, targetType=" wide
		$other5 = "hexMoudule(public key) cannot be null or empty." wide
		$other6 = "https://oauth2.googleapis.com/token" wide

	condition:
		5 of ( $other* )
}

rule VOLEXITY_Apt_Malware_Any_Reloadext_Plugin : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detection for RELOADEXT, a Google Chrome extension malware."
		author = "threatintel@volexity.com"
		id = "6c6c8bee-2a13-5645-89ef-779f00264fd9"
		date = "2024-02-23"
		modified = "2024-08-02"
		reference = "TIB-20240227"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L4-L36"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "2b11f8fc5b6260ebf00bde83585cd7469709a4979ca579cdf065724bc15052fc"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "9d0928b3cc21ee5e1f2868f692421165f46b5014a901636c2a2b32a4c500f761"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10282
		version = 4

	strings:
		$man1 = "Reload page with Internet Explorer compatible mode."
		$man2 = "\"http://*/*\""
		$code1 = ";chrome["
		$code2 = "XMLHttpRequest(),_"
		$code3 = "0x400*0x400"

	condition:
		all of ( $man* ) or ( #code1 > 8 and #code2 >= 2 and #code3 >= 2 )
}

rule VOLEXITY_Apt_Malware_Macos_Reloadext_Installer : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detect the RELOADEXT installer."
		author = "threatintel@volexity.com"
		id = "c65ea2b5-ab98-5693-92ea-05c0f1ea1e5b"
		date = "2024-02-23"
		modified = "2024-08-02"
		reference = "TIB-20240227"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L37-L62"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "8688796839202d95ded15e10262a7a7c7cbbae4a332b60305402e5984005d452"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "07e3b067dc5e5de377ce4a5eff3ccd4e6a2f1d7a47c23fe06b1ededa7aed1ab3"
		os = "darwin"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10281
		version = 2

	strings:
		$str1 = "/CustomPlug1n/"
		$str2 = "Chrome NOT installed."
		$str3 = "-f force kill Chrome"
		$str4 = "/*} &&cp -rf ${"

	condition:
		3 of them
}

rule VOLEXITY_Apt_Malware_Any_Macma_A : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detects variants of the MACMA backdoor, variants of MACMA have been discovered for macOS and android."
		author = "threatintel@volexity.com"
		id = "6ab45af1-41e5-53fc-9297-e2bc07ebf797"
		date = "2021-11-12"
		modified = "2024-08-02"
		reference = "https://blog.google/threat-analysis-group/analyzing-watering-hole-campaign-using-macos-exploits/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L63-L111"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "7ebaff9fddf6491d6b1ed9ab14c1b87dc8df850536e55aa723d625a593b33ed7"
		score = 75
		quality = 53
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"
		hash2 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
		hash3 = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
		hash4 = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
		os = "all"
		os_arch = "all"
		report1 = "TIB-20231221"
		report2 = "TIB-20240227"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6114
		version = 9

	strings:
		$magic1 = "curl -o %s http://cgi1.apnic.net/cgi-bin/my-ip.php" fullword ascii
		$magic2 = "[FST%d]: WhyUserCancel UNKNOW: %d" fullword ascii
		$magic3 = "[FST%d]: wait C2 prepare ready TIMEOUT, fd: %d" fullword ascii
		$magic4 = "[FST%d]: wait C2 ack file content TIMEOUT, fd: %d" fullword ascii
		$magic5 = "[FST%d]: TIMER_CHECK_CANCEL WhyUserCancel UNKNOW: %d" fullword ascii
		$magic6 = "[FST%d]: encrypt file info key=%s, crc v1=0x%p, v2=0x%p" fullword ascii
		$s1 = "auto bbbbbaaend:%d path %s" fullword ascii
		$s2 = "0keyboardRecirderStopv" fullword ascii
		$s3 = "curl begin..." fullword ascii
		$s4 = "curl over!" fullword ascii
		$s5 = "kAgent fail" fullword ascii
		$s6 = "put !!!!" fullword ascii
		$s7 = "vret!!!!!! %d" fullword ascii
		$s8 = "save Setting Success" fullword ascii
		$s9 = "Start Filesyste Search." fullword ascii
		$s10 = "./SearchFileTool" fullword ascii
		$s11 = "put unknow exception in MonitorQueue" fullword ascii
		$s12 = "./netcfg2.ini" fullword ascii
		$s13 = ".killchecker_" fullword ascii
		$s14 = "./param.ini" fullword ascii

	condition:
		any of ( $magic* ) or 7 of ( $s* )
}

rule VOLEXITY_Apt_Malware_Win_Dustpan_Apihashes : STORMBAMBOO FILE
{
	meta:
		description = "Detects DUSTPAN malware using API hashes used to resolve functions at runtime."
		author = "threatintel@volexity.com"
		id = "ed275da4-cd95-5fa3-a568-e610fb405bb3"
		date = "2023-08-17"
		modified = "2024-08-02"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L171-L205"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "3edb66ade428c451c18aa152244f869f9f8c10e62ed942bf722b4d1cf1893e93"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE"
		hash1 = "b77bcfb036f5a6a3973fdd68f40c0bd0b19af1246688ca4b1f9db02f2055ef9d"
		os = "win"
		os_arch = "all"
		report1 = "MAR-20230818"
		report2 = "TIB-20231221"
		scan_context = "file"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9591
		version = 3

	strings:
		$h1 = {9c 5b 9f 0b}
		$h2 = {4c 8f 3e 08}
		$h3 = {b4 aa f2 06}
		$h4 = {dc cb ca 09}
		$h5 = {d4 33 07 0e}
		$h6 = {27 89 d6 0a}
		$h7 = {b5 7d ae 09}
		$h8 = {4e 64 eb 0b}
		$h9 = {be 17 d9 08}
		$magic = "SMHM"

	condition:
		6 of ( $h* ) and $magic
}

rule VOLEXITY_Apt_Malware_Win_Pocostick_Jul23 : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detects the July 2023 POCOSTICK variant. These strings are only visible in memory after several rounds of shellcode decryption."
		author = "threatintel@volexity.com"
		id = "9632a7fc-06da-58b4-b95c-b46aeb9dd41d"
		date = "2023-07-24"
		modified = "2024-08-02"
		reference = "TIB-20231221"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L206-L235"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "19487db733c7f793be2a1287df32a165e46f6af0e940b13b389f4d675b5100c4"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		hash1 = "ec3e787c369ac4b28447e7cacc44d70a595e39d47f842bacb07d19b12cab6aad"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9542
		version = 3

	strings:
		$str1 = "Folder PATH listing form volume" wide
		$str2 = "Volume serial number is 0000-1111" wide
		$str3 = "Type:Error" wide
		$str4 = "Type:Desktop" wide
		$str5 = "Type:Laptop" wide
		$str6 = "Type:Vitual" wide
		$str7 = ".unicode.tmp" wide
		$str8 = "EveryOne" wide

	condition:
		6 of them
}

rule VOLEXITY_Apt_Malware_Py_Dustpan_Pyloader : STORMBAMBOO FILE MEMORY
{
	meta:
		description = "Detects Python script used by KPlayer to update, modified by attackers to download a malicious payload."
		author = "threatintel@volexity.com"
		id = "446d2eef-c60a-50ed-9ff1-df86b6210dff"
		date = "2023-07-21"
		modified = "2024-08-02"
		reference = "TIB-20231221"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L236-L270"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "bb3a70dad28181534e27abbbd618165652c137264bfd3726ae4480c642493a3b"
		score = 75
		quality = 80
		tags = "STORMBAMBOO, FILE, MEMORY"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9530
		version = 4

	strings:
		$s_1 = "def count_md5(src)"
		$s_2 = "urllib.request.urlretrieve(image_url,main)"
		$s_3 = "m1 != '4c8a326899272d2fe30e818181f6f67f'"
		$s_4 = "os.path.split(os.path.realpath(__file__))[0]"
		$s_5 = "r_v = os.system('curl '+ini_url+cc)"
		$s_6 = "b41ef5f591226a0d5adce99cb2e629d8"
		$s_7 = "1df495e7c85e59ad0de1b9e50912f8d0"
		$s_8 = "tasklist | findstr mediainfo.exe"
		$url_1 = "http://dl1.5kplayer.com/youtube/youtube_dl.png"
		$url_2 = "http://dl1.5kplayer.com/youtube/youtube.ini?fire="
		$path_1 = "C:\\\\ProgramData\\\\Digiarty\\\\mediainfo.exe"

	condition:
		3 of ( $s_* ) or any of ( $url_* ) or $path_1
}

