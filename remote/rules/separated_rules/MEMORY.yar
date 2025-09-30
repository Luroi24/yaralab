rule VOLEXITY_Apt_Malware_Win_Avburner : DEVIOUSBAMBOO FILE MEMORY
{
	meta:
		description = "Detects AVBurner based on a combination of API calls used, hard-coded strings and bytecode patterns."
		author = "threatintel@volexity.com"
		id = "1bde0861-4820-5bb1-98a3-516092c91be0"
		date = "2023-01-02"
		modified = "2024-08-16"
		reference = "https://www.trendmicro.com/en_us/research/22/k/hack-the-real-box-apt41-new-subgroup-earth-longzhi.html"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-03-07 AVBurner/yara.yar#L1-L40"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "4b1b1a1293ccd2c0fd51075de9376ebb55ab64972da785153fcb0a4eb523a5eb"
		logic_hash = "56ff6c8a4b737959a1219699a0457de1f0c34fead4299033840fb23c56a0caad"
		score = 75
		quality = 80
		tags = "DEVIOUSBAMBOO, FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8780
		version = 4

	strings:
		$api1 = "PspCreateProcessNotifyRoutineAddress" wide
		$api2 = "PspCreateThreadNotifyRoutineAddress" wide
		$api3 = "PspLoadImageNotifyRoutineAddress" wide
		$str1 = "\\\\.\\RTCORE64" wide
		$str2 = "\\\\%ws/pipe/%ws" wide
		$str3 = "CreateServerW Failed %u" wide
		$str4 = "OpenSCManager Failed %u" wide
		$str5 = "Get patternAddress" wide
		$pattern1 = { 4C 8B F9 48 8D 0C C1 E8 }
		$pattern2 = { 48 8D 0C DD 00 00 00 00  45 33 C0 49 03 CD 48 8B }
		$pattern3 = { 48 8D 04 C1 48 89 45 70 48 8B C8 E8 }
		$pattern4 = { 49 8D 0C FC 45 33 C0 48 8B D6 E8 00 00 00 00 00}
		$pattern5 = { 45 33 C0 48 8D 0C D9 48 8B D7 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$pattern6 = { 41 0F BA 6D 00 0A BB 01 00 00 00 4C 8B F2 4C 8B F9 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		all of ( $api* ) or all of ( $str* ) or all of ( $pattern* )
}

rule VOLEXITY_Webshell_Java_Behinder_Shellservice : FILE MEMORY
{
	meta:
		description = "Looks for artifacts generated (generally seen in .class files) related to the Behinder webshell."
		author = "threatintel@volexity.com"
		id = "21c1e3e9-d048-5c60-9c21-8e54b27f359a"
		date = "2022-03-18"
		modified = "2024-07-30"
		reference = "https://github.com/MountCloud/BehinderClientSource/blob/master/src/main/java/net/rebeyond/behinder/core/ShellService.java"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L1-L29"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "373a8d4ef81e9bbbf1f24ebf0389e7da4b73f88786cc8e1d286ccc9f4c36debc"
		score = 75
		quality = 30
		tags = "FILE, MEMORY"
		hash1 = "9a9882f9082a506ed0fc4ddaedd50570c5762deadcaf789ac81ecdbb8cf6eff2"
		os = "win,linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6615
		version = 3

	strings:
		$s1 = "CONNECT" ascii fullword
		$s2 = "DISCONNECT" ascii fullword
		$s3 = "socket_" ascii fullword
		$s4 = "targetIP" ascii fullword
		$s5 = "targetPort" ascii fullword
		$s6 = "socketHash" ascii fullword
		$s7 = "extraData" ascii fullword

	condition:
		all of them
}

rule VOLEXITY_Malware_Golang_Pantegana : FILE MEMORY
{
	meta:
		description = "Detects PANTEGANA, a Golang backdoor used by a range of threat actors due to its public availability."
		author = "threatintel@volexity.com"
		id = "b6154165-68e0-5986-a0cf-5631d369c230"
		date = "2022-03-30"
		modified = "2025-03-21"
		reference = "https://github.com/elleven11/pantegana"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L89-L119"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "791a664a6b4b98051cbfacb451099de085cbab74d73771709377ab68a5a23d2b"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "8297c99391aae918f154077c61ea94a99c7a339166e7981d9912b7fdc2e0d4f0"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6631
		version = 3

	strings:
		$s1 = "RunFingerprinter" ascii
		$s2 = "SendSysInfo" ascii
		$s3 = "ExecAndGetOutput" ascii
		$s4 = "RequestCommand" ascii
		$s5 = "bindataRead" ascii
		$s6 = "RunClient" ascii
		$magic = "github.com/elleven11/pantegana" ascii

	condition:
		5 of ( $s* ) or $magic
}

rule VOLEXITY_Malware_Any_Pupyrat_B : FILE MEMORY
{
	meta:
		description = "Detects the PUPYRAT malware family, a cross-platform RAT written in Python."
		author = "threatintel@volexity.com"
		id = "ec8d0448-f47d-5c6e-bcf9-8f40ae83a96f"
		date = "2022-04-07"
		modified = "2025-03-21"
		reference = "https://github.com/n1nj4sec/pupy"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L120-L157"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "f5b5f35ee783ff1163072591c6d48a85894729156935650a0fd166ae22a2ea00"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "7474a6008b99e45686678f216af7d6357bb70a054c6d9b05e1817c8d80d536b4"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6689
		version = 4

	strings:
		$elf1 = "LD_PRELOAD=%s HOOK_EXIT=%d CLEANUP=%d exec %s 1>/dev/null 2>/dev/null" ascii
		$elf2 = "reflective_inject_dll" fullword ascii
		$elf3 = "ld_preload_inject_dll" fullword ascii
		$pupy1 = "_pupy.error" ascii
		$pupy2 = "pupy://" ascii
		$s1 = "Args not passed" ascii
		$s2 = "Too many args" ascii
		$s3 = "Can't execute" ascii
		$s4 = "mexec:stdin" ascii
		$s5 = "mexec:stdout" ascii
		$s6 = "mexec:stderr" ascii
		$s7 = "LZMA error" ascii

	condition:
		any of ( $elf* ) or all of ( $pupy* ) or all of ( $s* )
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_Oct22 : LAZYPINE FILE MEMORY
{
	meta:
		description = "Detects AppleJeus DLL samples."
		author = "threatintel@volexity.com"
		id = "f88e2253-e296-57d8-a627-6cb4ccff7a92"
		date = "2022-11-03"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L1-L22"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "46f3325a7e8e33896862b1971f561f4871670842aecd46bcc7a5a1af869ecdc4"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "82e67114d632795edf29ce1d50a4c1c444846d9e16cd121ce26e63c8dc4a1629"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8495
		version = 3

	strings:
		$s1 = "HijackingLib.dll" ascii

	condition:
		$s1
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_B_Oct22 : LAZYPINE FILE MEMORY
{
	meta:
		description = "Detects unpacked AppleJeus samples."
		author = "threatintel@volexity.com"
		id = "8586dc64-225b-5f28-a6d6-b9b6e8f1c815"
		date = "2022-11-03"
		modified = "2025-05-21"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L24-L54"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "76f3c9692ea96d3cadbbcad03477ab6c53445935352cb215152b9b5483666d43"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "9352625b3e6a3c998e328e11ad43efb5602fe669aed9c9388af5f55fadfedc78"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8497
		version = 5

	strings:
		$key1 = "AppX7y4nbzq37zn4ks9k7amqjywdat7d"
		$key2 = "Gd2n5frvG2eZ1KOe"
		$str1 = "Windows %d(%d)-%s"
		$str2 = "&act=check"

	condition:
		( any of ( $key* ) and 1 of ( $str* ) ) or all of ( $str* )
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_C_Oct22 : LAZYPINE MEMORY
{
	meta:
		description = "Detects unpacked AppleJeus samples."
		author = "threatintel@volexity.com"
		id = "c9cbddde-220c-5e26-8760-85c29b98bfeb"
		date = "2022-11-03"
		modified = "2023-09-28"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L57-L84"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "a9e635d9353c8e5c4992beba79299fb889a7a3d5bc3eaf191f8bb7f51258a6c6"
		score = 75
		quality = 80
		tags = "LAZYPINE, MEMORY"
		hash1 = "a0db8f8f13a27df1eacbc01505f311f6b14cf9b84fbc7e84cb764a13f001dbbb"
		os = "win"
		os_arch = "all"
		scan_context = "memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8519
		version = 3

	strings:
		$str1 = "%sd.e%sc \"%s > %s 2>&1\"" wide
		$str2 = "tuid"
		$str4 = "payload"
		$str5 = "fconn"
		$str6 = "Mozilla_%lu"

	condition:
		5 of ( $str* )
}

rule VOLEXITY_Apt_Malware_Win_Applejeus_D_Oct22 : LAZYPINE FILE MEMORY
{
	meta:
		description = "Detected AppleJeus unpacked samples."
		author = "threatintel@volexity.com"
		id = "80d2821b-a437-573e-9e9d-bf79f9422cc9"
		date = "2022-11-10"
		modified = "2025-05-21"
		reference = "https://www.volexity.com/blog/2022/12/01/buyer-beware-fake-cryptocurrency-applications-serving-as-front-for-applejeus-malware/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L87-L112"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "23c0642e5be15a75a39d089cd52f2f14d633f7af6889140b9ec6e53c5c023974"
		score = 75
		quality = 80
		tags = "LAZYPINE, FILE, MEMORY"
		hash1 = "a241b6611afba8bb1de69044115483adb74f66ab4a80f7423e13c652422cb379"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 8534
		version = 3

	strings:
		$reg = "Software\\Bitcoin\\Bitcoin-Qt"
		$pattern = "%s=%d&%s=%s&%s=%s&%s=%d"
		$exec = " \"%s\", RaitingSetupUI "
		$http = "Accept: */*" wide

	condition:
		all of them
}

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

rule VOLEXITY_Susp_Jsp_General_Runtime_Exec_Req : FILE MEMORY
{
	meta:
		description = "Looks for a common design pattern in webshells where a request attribute is passed as an argument to exec()."
		author = "threatintel@volexity.com"
		id = "7f1539bd-a2f0-50dd-b500-ada4e0971d13"
		date = "2022-02-02"
		modified = "2024-07-30"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L35-L56"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "d3048aba80c1c39f1673931cd2d7c5ed83045603b0ad204073fd788d0103a6c8"
		score = 65
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "4935f0c50057e28efa7376c734a4c66018f8d20157b6584399146b6c79a6de15"
		os = "win,linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6450
		version = 3

	strings:
		$s1 = "Runtime.getRuntime().exec(request." ascii

	condition:
		$s1
}

rule VOLEXITY_Webshell_Jsp_Regeorg : FILE MEMORY
{
	meta:
		description = "Detects the reGeorg webshells' JSP version."
		author = "threatintel@volexity.com"
		id = "205ee383-4298-5469-a509-4ce3eaf9dd0e"
		date = "2022-03-08"
		modified = "2024-09-20"
		reference = "https://github.com/SecWiki/WebShell-2/blob/master/reGeorg-master/tunnel.jsp"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-08-10 Mass exploitation of (Un)authenticated Zimbra RCE CVE-2022-27925/yara.yar#L57-L86"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "cecb71605d9112d509823c26e40e1cf9cd6db581db448db5c9ffc63a2bfe529e"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "f9b20324f4239a8c82042d8207e35776d6777b6305974964cd9ccc09d431b845"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6575
		version = 5

	strings:
		$magic = "socketChannel.connect(new InetSocketAddress(target, port))" ascii
		$a1 = ".connect(new InetSocketAddress" ascii
		$a2 = ".configureBlocking(false)" ascii
		$a3 = ".setHeader(" ascii
		$a4 = ".getHeader(" ascii
		$a5 = ".flip();" ascii

	condition:
		$magic or all of ( $a* )
}

rule VOLEXITY_Webshell_Java_Realcmd : FILE MEMORY
{
	meta:
		description = "Detects the RealCMD webshell, one of the payloads for BEHINDER."
		author = "threatintel@volexity.com"
		id = "60b30ccc-bcfa-51e6-a3f5-88037d19213e"
		date = "2022-06-01"
		modified = "2024-07-30"
		reference = "https://github.com/Freakboy/Behinder/blob/master/src/main/java/vip/youwe/sheller/payload/java/RealCMD.java"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2022/2022-06-02 Active Exploitation Of Confluence 0-day/indicators/yara.yar#L61-L84"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "e09f2a23674fd73296dd4d1fabf1a2c812bfe69ff02abc96a4be35af6a18e512"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6786
		version = 4

	strings:
		$fn1 = "runCmd" wide ascii fullword
		$fn2 = "RealCMD" ascii wide fullword
		$fn3 = "buildJson" ascii wide fullword

	condition:
		all of ( $fn* )
}

rule VOLEXITY_Webshell_Aspx_Regeorgtunnel : FILE MEMORY
{
	meta:
		description = "A variation of the reGeorgtunnel open-source webshell."
		author = "threatintel@volexity.com"
		id = "b8aa27c9-a28a-5051-8f81-1184f28842ed"
		date = "2021-03-02"
		modified = "2024-10-18"
		reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-03-02 - Operation Exchange Marauder/indicators/yara.yar#L26-L56"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
		logic_hash = "ea3d0532cb609682922469e8272dc8061efca3b3ae27df738ef2646e30404c6f"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 4979
		version = 4

	strings:
		$s1 = "System.Net.Sockets"
		$s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"
		$t1 = ".Split('|')"
		$t2 = "Request.Headers.Get"
		$t3 = ".Substring("
		$t4 = "new Socket("
		$t5 = "IPAddress ip;"

	condition:
		all of ( $s* ) or all of ( $t* )
}

rule VOLEXITY_Apt_Webshell_Aspx_Sportsball : FILE MEMORY
{
	meta:
		description = "The SPORTSBALL webshell, observed in targeted Microsoft Exchange attacks."
		author = "threatintel@volexity.com"
		id = "25b23a4c-8fc7-5d6f-b4b5-46fe2c1546d8"
		date = "2021-03-01"
		modified = "2024-07-30"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-03-02 - Operation Exchange Marauder/indicators/yara.yar#L57-L88"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
		logic_hash = "5ec5e52922e97a3080d397b69b2f42f09daa995271e218ea085fa2ec4e3abad2"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 4968
		version = 5

	strings:
		$uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
		$uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="
		$s1 = "Result.InnerText = string.Empty;"
		$s2 = "newcook.Expires = DateTime.Now.AddDays("
		$s3 = "System.Diagnostics.Process process = new System.Diagnostics.Process();"
		$s4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
		$s5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
		$s6 = "<input type=\"submit\" value=\"Upload\" />"

	condition:
		any of ( $uniq* ) or all of ( $s* )
}

rule VOLEXITY_Malware_Win_Backwash_Cpp : WHEELEDASH FILE MEMORY
{
	meta:
		description = "CPP loader for the Backwash malware."
		author = "threatintel@volexity.com"
		id = "8a1c4ff1-1827-5e6f-b838-664d8c3be840"
		date = "2021-11-17"
		modified = "2023-11-13"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L3-L26"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "c8ed2d3103aa85363acd7f5573aeb936a5ab5a3bacbcf1f04e6b298299f24dae"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		hash1 = "0cf93de64aa4dba6cec99aa5989fc9c5049bc46ca5f3cb327b49d62f3646a852"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6147
		version = 2

	strings:
		$s1 = "cor1dbg.dll" wide
		$s2 = "XEReverseShell.exe" wide
		$s3 = "XOJUMAN=" wide

	condition:
		2 of them
}

rule VOLEXITY_Malware_Win_Iis_Shellsave : WHEELEDASH FILE MEMORY
{
	meta:
		description = "Detects an AutoIT backdoor designed to run on IIS servers and to install a webshell."
		author = "threatintel@volexity.com"
		id = "a89defa5-4b22-5650-a0c0-f4b3cf3377a7"
		date = "2021-11-17"
		modified = "2023-08-17"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L27-L49"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "f34d6f4ecaa4cde5965f6b0deac55c7133a2be96f5c466f34775be6e7f730493"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		hash1 = "21683e02e11c166d0cf616ff9a1a4405598db7f4adfc87b205082ae94f83c742"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6146
		version = 4

	strings:
		$s1 = "getdownloadshell" ascii
		$s2 = "deleteisme" ascii
		$s3 = "sitepapplication" ascii
		$s4 = "getapplicationpool" ascii

	condition:
		all of them
}

rule VOLEXITY_Malware_Win_Backwash_Iis_Scout : WHEELEDASH FILE MEMORY
{
	meta:
		description = "Simple backdoor which collects information about the IIS server it is installed on. It appears to the attacker refers to this components as 'XValidate' - i.e. to validate infected machines."
		author = "threatintel@volexity.com"
		id = "1f768b39-21a0-574d-9043-5104540003f7"
		date = "2021-11-17"
		modified = "2023-08-17"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L50-L78"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "18c4e338905ff299d75534006037e63a8f9b191f062cc97b0592245518015f88"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		hash1 = "6f44a9c13459533a1f3e0b0e698820611a18113c851f763797090b8be64fd9d5"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 6145
		version = 3

	strings:
		$s1 = "SOAPRequest" ascii
		$s2 = "requestServer" ascii
		$s3 = "getFiles" ascii
		$s4 = "APP_POOL_CONFIG" wide
		$s5 = "<virtualDirectory" wide
		$s6 = "stringinstr" ascii
		$s7 = "504f5354" wide
		$s8 = "XValidate" ascii
		$s9 = "XEReverseShell" ascii
		$s10 = "XERsvData" ascii

	condition:
		6 of them
}

rule VOLEXITY_Malware_Win_Backwash_Iis : WHEELEDASH FILE MEMORY
{
	meta:
		description = "Variant of the BACKWASH malware family with IIS worm functionality."
		author = "threatintel@volexity.com"
		id = "08a86a58-32af-5c82-90d2-d6603dae8d63"
		date = "2020-09-04"
		modified = "2023-08-17"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-12-06 - XEGroup/indicators/yara.yar#L181-L208"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "98e39573a3d355d7fdf3439d9418fdbf4e42c2e03051b5313d5c84f3df485627"
		logic_hash = "95a7f9e0afb031b49cd0da66b5a887d26ad2e06cce625bc45739b4a80e96ce9c"
		score = 75
		quality = 80
		tags = "WHEELEDASH, FILE, MEMORY"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 231
		version = 6

	strings:
		$a1 = "GetShell" ascii
		$a2 = "smallShell" ascii
		$a3 = "createSmallShell" ascii
		$a4 = "getSites" ascii
		$a5 = "getFiles " ascii
		$b1 = "action=saveshell&domain=" ascii wide
		$b2 = "&shell=backsession.aspx" ascii wide

	condition:
		all of ( $a* ) or any of ( $b* )
}

rule VOLEXITY_Apt_Malware_Win_Flipflop_Ldr : COZYLARCH FILE MEMORY
{
	meta:
		description = "A loader for the CobaltStrike malware family, which ultimately takes the first and second bytes of an embedded file, and flips them prior to executing the resulting payload."
		author = "threatintel@volexity.com"
		id = "58696a6f-55a9-5212-9372-a539cc327e6b"
		date = "2021-05-25"
		modified = "2025-05-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L3-L26"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
		logic_hash = "a79d2b0700ae14f7a2af23c8f7df3df3564402b1137478008ccabefea0f543ad"
		score = 75
		quality = 80
		tags = "COZYLARCH, FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5443
		version = 6

	strings:
		$s1 = "irnjadle"
		$s2 = "BADCFEHGJILKNMPORQTSVUXWZY"
		$s3 = "iMrcsofo taBesC yrtpgoarhpciP orived r1v0."

	condition:
		all of ( $s* )
}

rule VOLEXITY_Malware_Win_Cobaltstrike_D : FILE MEMORY
{
	meta:
		description = "The CobaltStrike malware family, variant D."
		author = "threatintel@volexity.com"
		id = "89a2459b-314b-513e-bd1a-8c4239a30338"
		date = "2021-05-25"
		modified = "2024-11-22"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-05-27 - Suspected APT29 Operation Launches Election Fraud Themed Phishing Campaigns/indicators/yara.yar#L27-L54"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "b041efb8ba2a88a3d172f480efa098d72eef13e42af6aa5fb838e6ccab500a7c"
		logic_hash = "751b6832f2952d369cb616b28ac009d7bfcc4d92bf2db36d87d69bc1e9fa6c75"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5445
		version = 5

	strings:
		$s1 = "%s (admin)" fullword
		$s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
		$s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
		$s4 = "%s as %s\\%s: %d" fullword
		$s5 = "%s&%s=%s" fullword
		$s6 = "rijndael" fullword
		$s7 = "(null)"

	condition:
		6 of ( $s* )
}

rule VOLEXITY_Apt_Malware_Rb_Rokrat_Loader : INKYPINE FILE MEMORY
{
	meta:
		description = "Ruby loader seen loading the ROKRAT malware family."
		author = "threatintel@volexity.com"
		id = "69d09560-a769-55d3-a442-e37f10453cde"
		date = "2021-06-22"
		modified = "2024-08-22"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L1-L32"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "30ae14fd55a3ab60e791064f69377f3b9de9b871adfd055f435df657f89f8007"
		score = 75
		quality = 55
		tags = "INKYPINE, FILE, MEMORY"
		hash1 = "5bc52f6c1c0d0131cee30b4f192ce738ad70bcb56e84180f464a5125d1a784b2"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5598
		version = 7

	strings:
		$magic1 = "'https://update.microsoft.com/driverupdate?id=" ascii wide
		$magic2 = "sVHZv1mCNYDO0AzI';" ascii wide
		$magic3 = "firoffset..scupd.size" ascii wide
		$magic4 = /alias UrlFilter[0-9]{2,5} eval;"/
		$s1 = "clRnbp9GU6oTZsRGZpZ"
		$s2 = "RmlkZGxlOjpQb2ludGVy"
		$s3 = "yVGdul2bQpjOlxGZklmR"
		$s4 = "XZ05WavBlO6UGbkRWaG"

	condition:
		any of ( $magic* ) or any of ( $s* )
}

rule VOLEXITY_Apt_Malware_Win_Decrok : INKYPINE FILE MEMORY
{
	meta:
		description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
		author = "threatintel@volexity.com"
		id = "46be1793-6419-54fe-a78b-5d087e02626e"
		date = "2021-06-23"
		modified = "2023-09-28"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-24 - InkySquid Part 2/indicators/yara.yar#L62-L90"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
		logic_hash = "a551700943d5abc95af00fc4fefd416ace8d59037852c6bc5caf1d6bd09afd63"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE, MEMORY"
		os = "win"
		os_arch = "x86"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5606
		version = 4

	strings:
		$v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}
		$av1 = "Select * From AntiVirusProduct" wide
		$av2 = "root\\SecurityCenter2" wide
		$func1 = "CreateThread"
		$format = "%02x"

	condition:
		all of them and $func1 in ( @format .. @format + 10 )
}

rule VOLEXITY_Apt_Malware_Win_Dolphin : INKYPINE FILE MEMORY
{
	meta:
		description = "North Korean origin malware which uses a custom Google App for c2 communications."
		author = "threatintel@volexity.com"
		id = "27bb2b41-f77d-5b95-b555-206c39ed9e6c"
		date = "2021-06-21"
		modified = "2025-01-27"
		reference = "https://www.welivesecurity.com/2022/11/30/whos-swimming-south-korean-waters-meet-scarcrufts-dolphin/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-17 - InkySquid Part 1/indicators/yara.yar#L1-L77"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "785a92087efc816c88c6eed6363c432d8d45198fbd5cef84c04dabd36b6316a6"
		score = 75
		quality = 55
		tags = "INKYPINE, FILE, MEMORY"
		hash1 = "837eaf7b736583497afb8bbdb527f70577901eff04cc69d807983b233524bfed"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5593
		version = 10

	strings:
		$magic = "host_name: %ls, cookie_name: %s, cookie: %s, CT: %llu, ET: %llu, value: %s, path: %ls, secu: %d, http: %d, last: %llu, has: %d"
		$f1 = "%ls.INTEG.RAW" wide
		$f2 = "edb.chk" ascii
		$f3 = "edb.log" ascii
		$f4 = "edbres00001.jrs" ascii
		$f5 = "edbres00002.jrs" ascii
		$f6 = "edbtmp.log" ascii
		$f7 = "cheV01.dat" ascii
		$chrome1 = "Failed to get chrome cookie"
		$chrome2 = "mail.google.com, cookie_name: OSID"
		$chrome3 = ".google.com, cookie_name: SID,"
		$chrome4 = ".google.com, cookie_name: __Secure-3PSID,"
		$chrome5 = "Failed to get Edge cookie"
		$chrome6 = "google.com, cookie_name: SID,"
		$chrome7 = "google.com, cookie_name: __Secure-3PSID,"
		$chrome8 = "Failed to get New Edge cookie"
		$chrome9 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0"
		$chrome10 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
		$chrome11 = "Cookie: SID=%s; OSID=%s; __Secure-3PSID=%s"
		$chrome12 = "https://mail.google.com"
		$chrome13 = "result.html"
		$chrome14 = "GM_ACTION_TOKEN"
		$chrome15 = "GM_ID_KEY="
		$chrome16 = "/mail/u/0/?ik=%s&at=%s&view=up&act=prefs"
		$chrome17 = "p_bx_ie=1"
		$chrome18 = "myaccount.google.com, cookie_name: OSID"
		$chrome19 = "Accept-Language: ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3"
		$chrome20 = "Content-Type: application/x-www-form-urlencoded;charset=utf-8"
		$chrome21 = "Cookie: SID=%s; OSID=%s; __Secure-3PSID=%s"
		$chrome22 = "https://myaccount.google.com"
		$chrome23 = "result.html"
		$chrome24 = "myaccount.google.com"
		$chrome25 = "/_/AccountSettingsUi/data/batchexecute"
		$chrome26 = "f.req=%5B%5B%5B%22BqLdsd%22%2C%22%5Btrue%5D%22%2Cnull%2C%22generic%22%5D%5D%5D&at="
		$chrome27 = "response.html"
		$msg1 = "https_status is %s"
		$msg2 = "Success to find GM_ACTION_TOKEN and GM_ID_KEY"
		$msg3 = "Failed to find GM_ACTION_TOKEN and GM_ID_KEY"
		$msg4 = "Failed HttpSendRequest to mail.google.com"
		$msg5 = "Success to enable imap"
		$msg6 = "Failed to enable imap"
		$msg7 = "Success to find SNlM0e"
		$msg8 = "Failed to find SNlM0e"
		$msg9 = "Failed HttpSendRequest to myaccount.google.com"
		$msg10 = "Success to enable thunder access"
		$msg11 = "Failed to enable thunder access"

	condition:
		$magic or ( all of ( $f* ) and 3 of ( $chrome* ) ) or 24 of ( $chrome* ) or 4 of ( $msg* )
}

rule VOLEXITY_Apt_Malware_Win_Bluelight : INKYPINE FILE MEMORY
{
	meta:
		description = "The BLUELIGHT malware family. Leverages Microsoft OneDrive for network communications."
		author = "threatintel@volexity.com"
		id = "5bfdc74b-592e-5f3d-9fb8-bbbbd0f6f0f6"
		date = "2021-04-23"
		modified = "2025-02-18"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2021/2021-08-17 - InkySquid Part 1/indicators/yara.yar#L78-L120"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "45490dfc793bb95f153c0194989b25e0b2641fa9b9f6763d5733eab6483ffead"
		score = 75
		quality = 80
		tags = "INKYPINE, FILE, MEMORY"
		hash1 = "7c40019c1d4cef2ffdd1dd8f388aaba537440b1bffee41789c900122d075a86d"
		hash2 = "94b71ee0861cc7cfbbae53ad2e411a76f296fd5684edf6b25ebe79bf6a2a600a"
		hash3 = "485246b411ef5ea9e903397a5490d106946a8323aaf79e6041bdf94763a0c028"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 5284
		version = 12

	strings:
		$pdb1 = "\\Development\\BACKDOOR\\ncov\\"
		$pdb2 = "Release\\bluelight.pdb" nocase ascii
		$pdb3 = "D:\\Development\\GOLD-BACKDOOR\\Release\\FirstBackdoor.pdb"
		$pdb4 = "GOLD-BACKDOOR\\Release\\"
		$msg0 = "https://ipinfo.io" fullword
		$msg1 = "country" fullword
		$msg5 = "\"UserName\":\"" fullword
		$msg7 = "\"ComName\":\"" fullword
		$msg8 = "\"OS\":\"" fullword
		$msg9 = "\"OnlineIP\":\"" fullword
		$msg10 = "\"LocalIP\":\"" fullword
		$msg11 = "\"Time\":\"" fullword
		$msg12 = "\"Compiled\":\"" fullword
		$msg13 = "\"Process Level\":\"" fullword
		$msg14 = "\"AntiVirus\":\"" fullword
		$msg15 = "\"VM\":\"" fullword

	condition:
		any of ( $pdb* ) or all of ( $msg* )
}

rule VOLEXITY_Apt_Malware_Vbs_Basicstar_A : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		description = "VBS backdoor which bares architectural similarity to the POWERSTAR malware family."
		author = "threatintel@volexity.com"
		id = "e790defe-2bd5-5629-8420-ce8091483589"
		date = "2024-01-04"
		modified = "2025-05-21"
		reference = "TIB-20240111"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L68-L98"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "977bb42553bb6585c8d0e1e89675644720ca9abf294eccd797e20d4bca516810"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "c6f91e5585c2cbbb8d06b7f239e30b271f04393df4fb81815f6556fa4c793bb0"
		os = "win"
		os_arch = "all"
		report2 = "TIB-20240126"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10037
		version = 8

	strings:
		$s1 = "Base64Encode(EncSess)" ascii wide
		$s2 = "StrReverse(PlainSess)" ascii wide
		$s3 = "ComDecode, \"Module\"" ascii wide
		$s4 = "ComDecode, \"SetNewConfig\"" ascii wide
		$s5 = "ComDecode, \"kill\"" ascii wide
		$magic = "cmd /C start /MIN curl --ssl-no-revoke -s -d " ascii wide

	condition:
		3 of ( $s* ) or $magic
}

rule VOLEXITY_Apt_Malware_Ps1_Powerless_B : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		description = "Detects POWERLESS malware."
		author = "threatintel@volexity.com"
		id = "e62703b5-32fb-5ceb-9f21-f52a4871f3d9"
		date = "2023-10-25"
		modified = "2024-01-29"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L99-L156"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "eb9d199c1f7c2a42d711c1a44ab13526787169c18a77ce988568525baca043ef"
		score = 75
		quality = 78
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "62de7abb39cf4c47ff120c7d765749696a03f4fa4e3e84c08712bb0484306ae1"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9794
		version = 5

	strings:
		$fun_1 = "function verifyClickStorke"
		$fun_2 = "function ConvertTo-SHA256"
		$fun_3 = "function Convert-Tobase" fullword
		$fun_4 = "function Convert-Frombase" fullword
		$fun_5 = "function Send-Httppacket"
		$fun_6 = "function Generat-FetchCommand"
		$fun_7 = "function Create-Fetchkey"
		$fun_8 = "function Run-Uploader"
		$fun_9 = "function Run-Shot" fullword
		$fun_10 = "function ShotThis("
		$fun_11 = "function File-Manager"
		$fun_12 = "function zip-files"
		$fun_13 = "function Run-Stealer"
		$fun_14 = "function Run-Downloader"
		$fun_15 = "function Run-Stro" fullword
		$fun_16 = "function Run-Tele" fullword
		$fun_17 = "function Run-Voice"
		$s_1 = "if($commandtype -eq \"klg\")"
		$s_2 = "$desrilizedrecievedcommand"
		$s_3 = "$getAsyncKeyProto = @"
		$s_4 = "$Global:BotId ="
		$s_5 = "$targetCLSID = (Get-ScheduledTask | Where-Object TaskName -eq"
		$s_6 = "$burl = \"$Global:HostAddress/"
		$s_7 = "$hashString = [System.BitConverter]::ToString($hash).Replace('-','').ToLower()"
		$s_8 = "$Global:UID = ((gwmi win32_computersystemproduct).uuid -replace '[^0-9a-z]').substring("
		$s_9 = "$rawpacket = \"{`\"MId`\":`\"$Global:MachineID`\",`\"BotId`\":`\"$basebotid`\"}\""
		$s_12 = "Runned Without any Error"
		$s_13 = "$commandresponse = (Invoke-Expression $instruction -ErrorAction Stop) | Out-String"
		$s_14 = "Operation started successfuly"
		$s_15 = "$t_path = (Get-WmiObject Win32_Process -Filter \"name = '$process'\" | Select-Object CommandLine).CommandLine"
		$s_16 = "?{ $_.DisplayName -match \"Telegram Desktop\" } | %{$app_path += $_.InstallLocation }"
		$s_17 = "$chlids = get-ChildItem $t -Recurse -Exclude \"$t\\tdata\\user_data\""
		$s_18 = "if($FirsttimeFlag -eq $True)"
		$s_19 = "Update-Conf -interval $inter -url $url -next_url $next -conf_path $conf_path -key $config_key"

	condition:
		3 of ( $fun_* ) or any of ( $s_* )
}

rule VOLEXITY_Apt_Malware_Macos_Vpnclient_Cc_Oct23 : CHARMINGCYPRESS FILE MEMORY
{
	meta:
		description = "Detection for fake macOS VPN client used by CharmingCypress."
		author = "threatintel@volexity.com"
		id = "e0957936-dc6e-5de6-bb23-d0ef61655029"
		date = "2023-10-17"
		modified = "2023-10-27"
		reference = "TIB-20231027"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-02-13 CharmingCypress/rules.yar#L245-L271"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "da5e9be752648b072a9aaeed884b8e1729a14841e33ed6633a0aaae1f11bd139"
		score = 75
		quality = 80
		tags = "CHARMINGCYPRESS, FILE, MEMORY"
		hash1 = "11f0e38d9cf6e78f32fb2d3376badd47189b5c4456937cf382b8a574dc0d262d"
		os = "darwin,linux"
		os_arch = "all"
		parent_hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9770
		version = 3

	strings:
		$s1 = "networksetup -setsocksfirewallproxystate wi-fi off" ascii
		$s2 = "networksetup -setsocksfirewallproxy wi-fi ___serverAdd___ ___portNum___; networksetup -setsocksfirewallproxystate wi-fi on" ascii
		$s3 = "New file imported successfully." ascii
		$s4 = "Error in importing the File." ascii

	condition:
		2 of ( $s* )
}

rule VOLEXITY_Apt_Malware_Win_Deepdata_Module : BRAZENBAMBOO FILE MEMORY
{
	meta:
		description = "Detects modules used by DEEPDATA based on the required export names used by those modules."
		author = "threatintel@volexity.com"
		id = "1287f5dd-9229-57ce-a91a-73d61041df80"
		date = "2024-07-30"
		modified = "2024-11-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-11-15 BrazenBamboo/rules.yar#L1-L25"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "d36f34343826daf7f7368118c7127c7181a54c99a01803016c9a6965abb309cb"
		score = 75
		quality = 80
		tags = "BRAZENBAMBOO, FILE, MEMORY"
		hash1 = "c782346bf9e5c08a0c43a85d4991f26b0b3c99c054fa83beb4a9e406906f011e"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10868
		version = 2

	strings:
		$str1 = "ExecuteCommand"
		$str2 = "GetPluginCommandID"
		$str3 = "GetPluginName"
		$str4 = "GetPluginVersion"

	condition:
		all of them
}

rule VOLEXITY_Apt_Malware_Win_Lightspy_Orchestrator_Decoded_Core : BRAZENBAMBOO FILE MEMORY
{
	meta:
		description = "Detects the decoded orchestrator for the Windows variant of the LightSpy malware family. This file is normally stored in an encoded state on the C2 server and is used as the core component of this malware family, loading additional plugins from the C2 whilst managing all the C2 communication etc."
		author = "threatintel@volexity.com"
		id = "44f8d7a4-7f48-5960-91a7-baf475f7d291"
		date = "2024-02-15"
		modified = "2024-07-03"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-11-15 BrazenBamboo/rules.yar#L244-L287"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "f0189c0a84c53e365130e9683f2f2b2f73c14412d8e4d0251a4780d0e80162d8"
		score = 75
		quality = 78
		tags = "BRAZENBAMBOO, FILE, MEMORY"
		hash1 = "80c0cdb1db961c76de7e4efb6aced8a52cd0e34178660ef34c128be5f0d587df"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10246
		version = 2

	strings:
		$s1 = "Enter RunWork......."
		$s2 = "it's running......."
		$s3 = "select ret = socket_error."
		$s4 = "%s\\\\account.bin"
		$s5 = "[CtrlLink]: get machine sn err:%d"
		$s6 = "wmic path Win32_VideoController get CurrentHorizontalResolution,CurrentVerticalResolution /format:list | findstr /v \\\"^$\\\""
		$s7 = "wmic csproduct get vendor,version /format:list | findstr /v \\\"^$\\\""
		$s8 = "local ip get sockname error=%d"
		$s9 = "connect goole dns error=%d"
		$s10 = "%s/api/terminal/upsert/"
		$s11 = "/963852741/windows/plugin/manifest"
		$s12 = "Hello deepdata."
		$s13 = "Start Light."
		$s14 = "InitialPluginManager Error."
		$s15 = "InitialCommandExe Error."
		$s16 = "ws open, and send logon info."
		$s17 = "plugin_replay_handler"
		$s18 = "light_x86.dll"
		$pdb1 = "\\light\\bin\\light_x86.pdb"
		$pdb2 = "\\light\\bin\\plugin"
		$pdb3 = "D:\\tmpWork\\"

	condition:
		1 of ( $pdb* ) or 5 of ( $s* )
}

rule VOLEXITY_Apt_Malware_Win_Lightspy_Orchestrator_Decoded_C2_Strings : BRAZENBAMBOO FILE MEMORY
{
	meta:
		description = "Detects the decoded orchestrator for the Windows variant of the LightSpy malware family. This file is normally stored in an encoded state on the C2 server and is used as the core component of this malware family, loading additional plugins from the C2 whilst managing all the C2 communication etc."
		author = "threatintel@volexity.com"
		id = "a0af8fb7-13a3-54e8-8569-e8622fa80d89"
		date = "2024-02-15"
		modified = "2024-11-14"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-11-15 BrazenBamboo/rules.yar#L288-L337"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "eeaaf6e16d4854a2279bd62596f75cb8b8ec1b05f3b050f5dac97254704b9005"
		score = 75
		quality = 78
		tags = "BRAZENBAMBOO, FILE, MEMORY"
		hash1 = "80c0cdb1db961c76de7e4efb6aced8a52cd0e34178660ef34c128be5f0d587df"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10245
		version = 4

	strings:
		$s1 = "[WsClient][Error]:"
		$s2 = "[WsClient][Info]:"
		$s3 = "[WsClient]:WsClient"
		$s4 = "[WsClient][Info]:Ws"
		$s5 = "WsClient Worker Thread ID=%d"
		$s6 = "[LightWebClient]:"
		$s7 = "LightHttpGet err:%s"
		$s8 = "User-Agent: Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.145 Safari/537.36"
		$s9 = "KvList Err:%s"
		$s10 = "dataMultiPart malloc err:%d"
		$ctrl1 = "CTRL_HEART_BEAT"
		$ctrl2 = "CTRL_NET_CONFIG"
		$ctrl3 = "CTRL_COMMAND_PLAN"
		$ctrl4 = "CTRL_MODIFY_NET_CONFIG"
		$ctrl5 = "CTRL_UPLOAD_PLUGIN_STATUS"
		$ctrl6 = "CTRL_PLUGIN_EXECUTE_COMMAND"
		$ctrl7 = "CTRL_PLUGIN_COMMAND_STATUS"
		$ctrl8 = "CTRL_PLUGIN_STOP_COMMAND"
		$ctrl9 = "CTRL_GET_SLEEP_CONFIG"
		$ctrl10 = "CTRL_MODIFY_SLEEP_CONFIG"
		$ctrl11 = "CTRL_SLEEP_STATUS"
		$ctrl12 = "CTRL_UPDATE_PLUGIN"
		$ctrl13 = "CTRL_DESTROY"
		$ctrl14 = "CTRL_RECONFIG_REBOUNT_ADDRESS"
		$ctrl15 = "CTRL_AUTO_UPLOUD_FILE_CONFIG"
		$ctrl16 = "CTRL_UPLOUD_DEVICE_INFO"
		$ctrl17 = "CTRL_TEST_VPDN_ACCOUNT"

	condition:
		3 of ( $s* ) or 5 of ( $ctrl* )
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Modules : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI modules using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "b9e4ecdc-9b02-546f-9b79-947cb6b1f99a"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L1-L24"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "7880288e3230b688b780bdfbac2b0761fd7831b7df233672c2242c21a86e1297"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "2abaae4f6794131108adf5b42e09ee5ce24769431a0e154feabe6052cfe70bf3"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10270
		version = 6

	strings:
		$s1 = "discord-c2/test/main/finalizing/Deliveries/ob_Delivery.go" wide ascii
		$s2 = "discord-c2/test/main/finalizing/WAN_Conf.go" wide ascii

	condition:
		any of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Loader : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI loader using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "6d7848db-f1a5-5ccc-977a-7597b966a31c"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L25-L47"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "d9be4846bab5fffcfd60eaec377443819404f30ec088905c2ee26bd3b7525832"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "51a372fee89f885741515fa6fdf0ebce860f98145c9883f2e3e35c0fe4432885"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10269
		version = 7

	strings:
		$s1 = "discord-c2/test/main/delievery.go" wide ascii

	condition:
		$s1
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_Debug_String : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "eed2468f-7e50-5f3e-946a-277c10984823"
		date = "2024-02-22"
		modified = "2024-11-27"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L48-L71"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "6bb130eead39bd8128983e0f2e76cfeff8865ce8ed3cb73b132ed32d68fc0db0"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10268
		version = 9

	strings:
		$s1 = "discord-c2/test/main/payload.go" wide ascii
		$s2 = "Desktop/Golang_Dev/Discord"

	condition:
		any of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_2 : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects DISGOMOJI malware using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "609beb47-5e93-5f69-b89d-2cf62f20851a"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L72-L103"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "e03a774cca2946c1becdbd775ef465033dae089d578ea18a4f43fd7bdae9168e"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10266
		version = 9

	strings:
		$s1 = "downloadFileFromURL" wide ascii
		$s2 = "createCronJob" wide ascii
		$s3 = "findAndSendFiles" wide ascii
		$s4 = "updateLogFile" wide ascii
		$s5 = "handleZipFile" wide ascii
		$s6 = "takeScreenshot" wide ascii
		$s7 = "zipFirefoxProfile" wide ascii
		$s8 = "zipDirectoryWithParts" wide ascii
		$s9 = "uploadAndSendToOshi" wide ascii
		$s10 = "uploadAndSendToLeft" wide ascii

	condition:
		7 of them
}

rule VOLEXITY_Apt_Malware_Linux_Disgomoji_1 : TRANSPARENTJASMINE FILE MEMORY
{
	meta:
		description = "Detects GOMOJI malware using strings in the ELF."
		author = "threatintel@volexity.com"
		id = "f6643e9a-ca41-57e0-9fce-571d340f1cfe"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L104-L131"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "dd3535079881ae9cfe25c129803668cb595be89b7f62eb82af19cc3839f92b6d"
		score = 75
		quality = 80
		tags = "TRANSPARENTJASMINE, FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10265
		version = 7

	strings:
		$s1 = "Session *%s* opened!" wide ascii
		$s2 = "uevent_seqnum.sh" wide ascii
		$s3 = "Error downloading shell script: %v" wide ascii
		$s4 = "Error setting execute permissions: %v" wide ascii
		$s5 = "Error executing shell script: %v" wide ascii
		$s6 = "Error creating Discord session" wide ascii

	condition:
		4 of them
}

rule VOLEXITY_Malware_Golang_Discordc2_Bmdyy_1 : FILE MEMORY
{
	meta:
		description = "Detects a opensource malware available on github using strings in the binary. The DISGOMOJI malware family used by TransparentJasmine is based on this malware."
		author = "threatintel@volexity.com"
		id = "6816d264-4311-5e90-948b-2e27cdf0b720"
		date = "2024-03-28"
		modified = "2024-07-05"
		reference = "TIB-20240229"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L216-L243"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "22b3e5109d0738552fbc310344b2651ab3297e324bc883d5332c1e8a7a1df29b"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "de32e96d1f151cc787841c12fad88d0a2276a93d202fc19f93631462512fffaf"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10390
		version = 3

	strings:
		$s1 = "File is bigger than 8MB" wide ascii
		$s2 = "Uploaded file to" wide ascii
		$s3 = "sess-%d" wide ascii
		$s4 = "Session *%s* opened" wide ascii
		$s5 = "%s%d_%dx%d.png" wide ascii

	condition:
		4 of them
}

rule VOLEXITY_Malware_Golang_Discordc2_Bmdyy : FILE MEMORY
{
	meta:
		description = "Detects a opensource malware available on github using strings in the binary. DISGOMOJI used by TransparentJasmine is based on this malware."
		author = "threatintel@volexity.com"
		id = "1ddbf476-ba2d-5cbb-ad95-38e0ae8db71b"
		date = "2024-02-22"
		modified = "2024-07-05"
		reference = "https://github.com/bmdyy/discord-c2"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-06-13 DISGOMOJI/indicators/rules.yar#L244-L267"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "38b860a43b9937351f74b01983888f18ad101cbe66560feb7455d46b713eba0f"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10264
		version = 12

	strings:
		$s1 = "**IP**: %s\n**User**: %s\n**Hostname**: %s\n**OS**: %s\n**CWD**" wide ascii

	condition:
		$s1
}

rule VOLEXITY_Apt_Webshell_Aspx_Glasstoken : UTA0178 FILE MEMORY
{
	meta:
		description = "Detection for a custom webshell seen on Exchange server. The webshell contains two functions, the first is to act as a Tunnel, using code borrowed from reGeorg, the second is custom code to execute arbitrary .NET code."
		author = "threatintel@volexity.com"
		id = "2f07748a-a52f-5ac7-9d3e-50fd3ecea271"
		date = "2023-12-12"
		modified = "2024-09-30"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L26-L52"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "6b8183ac1e87a86c58760db51f767ed278cc0c838ed89e7435af7d0373e58b26"
		score = 75
		quality = 30
		tags = "UTA0178, FILE, MEMORY"
		hash1 = "26cbb54b1feb75fe008e36285334d747428f80aacdb57badf294e597f3e9430d"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 9994
		version = 6

	strings:
		$s1 = "=Convert.FromBase64String(System.Text.Encoding.Default.GetString(" ascii
		$re = /Assembly\.Load\(errors\)\.CreateInstance\("[a-z0-9A-Z]{4,12}"\).GetHashCode\(\);/

	condition:
		for any i in ( 0 .. math.min ( #s1 , 100 ) ) : ( $re in ( @s1 [ i ] .. @s1 [ i ] + 512 ) )
}

rule VOLEXITY_Webshell_Aspx_Regeorg : FILE MEMORY
{
	meta:
		description = "Detects the reGeorg webshell based on common strings in the webshell. May also detect other webshells which borrow code from ReGeorg."
		author = "threatintel@volexity.com"
		id = "02365a30-769e-5c47-8d36-a79608ffd121"
		date = "2018-08-29"
		modified = "2024-01-09"
		reference = "TIB-20231215"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L53-L86"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "9d901f1a494ffa98d967ee6ee30a46402c12a807ce425d5f51252eb69941d988"
		logic_hash = "4fed023e85a32052917f6db1e2e155c91586538938c03acc59f200a8264888ca"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		os = "win"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 410
		version = 7

	strings:
		$a1 = "every office needs a tool like Georg" ascii
		$a2 = "cmd = Request.QueryString.Get(\"cmd\")" ascii
		$a3 = "exKak.Message" ascii
		$proxy1 = "if (rkey != \"Content-Length\" && rkey != \"Transfer-Encoding\")"
		$proxy_b1 = "StreamReader repBody = new StreamReader(response.GetResponseStream(), Encoding.GetEncoding(\"UTF-8\"));" ascii
		$proxy_b2 = "string rbody = repBody.ReadToEnd();" ascii
		$proxy_b3 = "Response.AddHeader(\"Content-Length\", rbody.Length.ToString());" ascii

	condition:
		any of ( $a* ) or $proxy1 or all of ( $proxy_b* )
}

rule VOLEXITY_Hacktool_Py_Pysoxy : FILE MEMORY
{
	meta:
		description = "SOCKS5 proxy tool used to relay connections."
		author = "threatintel@volexity.com"
		id = "88094b55-784d-5245-9c40-b1eebf0e6e72"
		date = "2024-01-09"
		modified = "2024-01-09"
		reference = "TIB-20240109"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-01-10 Ivanti Connect Secure/indicators/yara.yar#L87-L114"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "f73e9d3c2f64c013218469209f3b69fc868efafc151a7de979dde089bfdb24b2"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "e192932d834292478c9b1032543c53edfc2b252fdf7e27e4c438f4b249544eeb"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10065
		version = 3

	strings:
		$s1 = "proxy_loop" ascii
		$s2 = "connect_to_dst" ascii
		$s3 = "request_client" ascii
		$s4 = "subnegotiation_client" ascii
		$s5 = "bind_port" ascii

	condition:
		all of them
}

rule VOLEXITY_Apt_Malware_Py_Upstyle : UTA0218 FILE MEMORY
{
	meta:
		description = "Detect the UPSTYLE webshell."
		author = "threatintel@volexity.com"
		id = "45726f35-8b3e-5095-b145-9e7f6da6838b"
		date = "2024-04-11"
		modified = "2024-04-12"
		reference = "TIB-20240412"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L1-L34"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "51923600b23d23f4ce29eac7f5ab9f7e1ddb45bed5f6727ddec4dcb75872e473"
		score = 75
		quality = 80
		tags = "UTA0218, FILE, MEMORY"
		hash1 = "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"
		hash2 = "0d59d7bddac6c22230187ef6cf7fa22bca93759edc6f9127c41dc28a2cea19d8"
		hash3 = "4dd4bd027f060f325bf6a90d01bfcf4e7751a3775ad0246beacc6eb2bad5ec6f"
		os = "linux"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10429
		version = 2

	strings:
		$stage1_str1 = "/opt/pancfg/mgmt/licenses/PA_VM"
		$stage1_str2 = "exec(base64."
		$stage2_str1 = "signal.signal(signal.SIGTERM,stop)"
		$stage2_str2 = "exec(base64."
		$stage3_str1 = "write(\"/*\"+output+\"*/\")"
		$stage3_str2 = "SHELL_PATTERN"

	condition:
		all of ( $stage1* ) or all of ( $stage2* ) or all of ( $stage3* )
}

rule VOLEXITY_Susp_Any_Jarischf_User_Path : FILE MEMORY
{
	meta:
		description = "Detects paths embedded in samples in released projects written by Ferdinand Jarisch, a pentester in AISEC. These tools are sometimes used by attackers in real world intrusions."
		author = "threatintel@volexity.com"
		id = "062a6fdb-c516-5643-9c7c-deff32eeb95e"
		date = "2024-04-10"
		modified = "2024-04-15"
		reference = "TIB-20240412"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L59-L81"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "574d5b1fadb91c39251600e7d73d4993d4b16565bd1427a0e8d6ed4e7905ab54"
		score = 50
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "high"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10424
		version = 4

	strings:
		$proj_1 = "/home/jarischf/"

	condition:
		any of ( $proj_* )
}

rule VOLEXITY_Hacktool_Golang_Reversessh_Fahrj : FILE MEMORY
{
	meta:
		description = "Detects a reverse SSH utility available on GitHub. Attackers may use this tool or similar tools in post-exploitation activity."
		author = "threatintel@volexity.com"
		id = "332e323f-cb16-5aa2-8b66-f3d6d50d94f2"
		date = "2024-04-10"
		modified = "2024-04-12"
		reference = "TIB-20240412"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar#L82-L116"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "38b40cc7fc1e601da2c7a825f1c2eff209093875a5829ddd2f4c5ad438d660f8"
		score = 75
		quality = 80
		tags = "FILE, MEMORY"
		hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
		os = "all"
		os_arch = "all"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 10423
		version = 5

	strings:
		$fun_1 = "createLocalPortForwardingCallback"
		$fun_2 = "createReversePortForwardingCallback"
		$fun_3 = "createPasswordHandler"
		$fun_4 = "createPublicKeyHandler"
		$fun_5 = "createSFTPHandler"
		$fun_6 = "dialHomeAndListen"
		$fun_7 = "createExtraInfoHandler"
		$fun_8 = "createSSHSessionHandler"
		$fun_9 = "createReversePortForwardingCallback"
		$proj_1 = "github.com/Fahrj/reverse-ssh"

	condition:
		any of ( $proj_* ) or 4 of ( $fun_* )
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

rule VOLEXITY_Apt_Malware_Elf_Catchdns_Aug20_Memory : DRIFTINGBAMBOO FILE MEMORY
{
	meta:
		description = "Looks for strings from CatchDNS component used to intercept and modify DNS responses, and likely also intercept/monitor http. This rule would only match against memory in the example file analyzed by Volexity."
		author = "threatintel@volexity.com"
		id = "95306735-cdae-5407-ad49-d465d245378d"
		date = "2020-08-20"
		modified = "2024-08-02"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2024/2024-08-02 StormBamboo/rules.yar#L309-L383"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		hash = "4f3d35f4f8b810362cbd4c59bfe5a961e559fe5713c9478294ccb3af2d306515"
		logic_hash = "a7d677d7eecf388df7e7c2343fd3e46188594473c01075bf8a0b54292a51db94"
		score = 75
		quality = 55
		tags = "DRIFTINGBAMBOO, FILE, MEMORY"
		os = "linux"
		os_arch = "all"
		report1 = "MAR-20221222"
		report2 = "TIB-20231221"
		scan_context = "file,memory"
		severity = "critical"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		rule_id = 227
		version = 10

	strings:
		$os1 = "current thread policy=%d" ascii wide
		$os2 = "OS_CreatShareMem %s-->%x" ascii wide
		$os3 = "sem_open fail" ascii wide
		$os4 = "int OS_GetCurRunPath(char*, int)" ascii wide
		$os5 = "int OS_GetCurModName(char*, int)" ascii wide
		$os6 = "int OS_StrToTime(char*, time_t*)" ascii wide
		$os7 = "int OS_TimeToStr(time_t, char*)" ascii wide
		$os8 = "int OS_TimeToStrYearMothDay(time_t, char*)" ascii wide
		$os9 = "bool OS_Access(const char*)" ascii wide
		$os10 = "int OS_Memicmp(const void*, const void*, unsigned int)" ascii wide
		$os11 = "int OS_Mkdir(char*)" ascii wide
		$os12 = "OS_ConnectSem" ascii wide
		$msg1 = "client: last send packet iseq: %x, the ack :%x" ascii wide
		$msg2 = "server: last send packet iseq: %x, the iseq :%x" ascii wide
		$msg3 = "send packet failed!" ascii wide
		$msg4 = "will hijack dns:%s, ip:%s " ascii wide
		$msg5 = "dns send ok:%s" ascii wide
		$msg6 = "tcp send ok" ascii wide
		$msg7 = "FilePath:%s;" ascii wide
		$msg8 = "Line:%d,Fun:%s,ErrorCode:%u;" ascii wide
		$msg9 = "Description:%s;" ascii wide
		$msg10 = "Line:%d,Fun:%s,ErrorCode:%u;" ascii wide
		$msg11 = "get msg from ini is error" ascii wide
		$msg12 = "on build eth send_msg or payload is null" ascii wide
		$msg13 = "on build udp send_msg or payload is null" ascii wide
		$conf1 = "%d.%d.%d.%d" ascii wide
		$conf2 = "%s.tty" ascii wide
		$conf3 = "dns.ini" ascii wide
		$netw1 = "LISTEN_DEV" ascii wide
		$netw2 = "SEND_DEV" ascii wide
		$netw3 = "SERVER_IP" ascii wide
		$netw4 = "DNSDomain" ascii wide
		$netw5 = "IpLimit" ascii wide
		$netw6 = "HttpConfig" ascii wide
		$netw7 = "buildhead" ascii wide
		$netw8 = "sendlimit" ascii wide
		$netw9 = "content-type" ascii wide
		$netw10 = "otherhead_" ascii wide
		$netw11 = "configfile" ascii wide
		$apache = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 53 65 72 76 65 72 3A 20 41 70 61 63 68 65 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 63 6C 6F 73 65 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 25 73 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A}
		$cpp1 = "src/os.cpp"
		$cpp2 = "src/test_catch_dns.cpp"

	condition:
		9 of ( $os* ) or 3 of ( $msg* ) or all of ( $conf* ) or all of ( $netw* ) or $apache or all of ( $cpp* )
}

rule DRAGON_THREAT_LABS_Apt_C16_Win_Memory_Pcclient : MEMORY APT
{
	meta:
		description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
		author = "@dragonthreatlab"
		id = "59333cd4-b532-510e-afe5-fc3b2e96698f"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L4-L19"
		license_url = "N/A"
		hash = "ec532bbe9d0882d403473102e9724557"
		logic_hash = "e863fcbcbde61db569a34509061732371143f38734a0213dc856dc3c9188b042"
		score = 75
		quality = 80
		tags = "MEMORY, APT"

	strings:
		$str1 = "Kill You" ascii
		$str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
		$str3 = "%4.2f  KB" ascii
		$encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}

	condition:
		all of them
}

rule DRAGON_THREAT_LABS_Apt_C16_Win_Swisyn : MEMORY FILE
{
	meta:
		description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
		author = "@dragonthreatlab"
		id = "af369075-aca3-576d-a10b-849703ffb4f1"
		date = "2015-01-11"
		modified = "2016-09-27"
		reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Dragonthreatlabs/dragonthreatlabs_index.yara#L54-L70"
		license_url = "N/A"
		hash = "a6a18c846e5179259eba9de238f67e41"
		logic_hash = "2fa29d3b17aa37501131132640953645d0089c9bc5ec13ffed7a498ad89c1558"
		score = 75
		quality = 28
		tags = "MEMORY, FILE"

	strings:
		$mz = {4D 5A}
		$str1 = "/ShowWU" ascii
		$str2 = "IsWow64Process"
		$str3 = "regsvr32 "
		$str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}

	condition:
		$mz at 0 and all of ( $str* )
}

rule SIGNATURE_BASE_APT_MAL_RU_WIN_Snake_Malware_May23_1 : MEMORY
{
	meta:
		description = "Hunting Russian Intelligence Snake Malware"
		author = "Matt Suiche (Magnet Forensics)"
		id = "53d2de3c-350c-5090-84bb-b6cde16a80ad"
		date = "2023-05-10"
		modified = "2025-03-21"
		reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_mal_ru_snake_may23.yar#L17-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "7cff7152259bb17a9b72b91f0fbef220aad2f35a1d2758d7225316a9896bf845"
		score = 70
		quality = 71
		tags = "MEMORY"
		threat_name = "Windows.Malware.Snake"
		scan_context = "memory"
		license = "MIT"

	strings:
		$a = { 25 73 23 31 }
		$b = { 25 73 23 32 }
		$c = { 25 73 23 33 }
		$d = { 25 73 23 34 }
		$e = { 2e 74 6d 70 }
		$g = { 2e 73 61 76 }
		$h = { 2e 75 70 64 }

	condition:
		all of them
}

