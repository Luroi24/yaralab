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

