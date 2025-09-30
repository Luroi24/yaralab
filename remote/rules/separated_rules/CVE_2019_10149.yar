rule DEADBITS_Watchdog_Botnet : BOTNET LINUXMALWARE EXPLOITATION CVE_2019_11581 CVE_2019_10149
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "ae95f934-2a9b-5c65-a11f-ea946d7f1bc6"
		date = "2019-07-22"
		modified = "2019-07-22"
		reference = "https://twitter.com/polarply/status/1153232987762376704"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/WatchBog_Linux.yara#L1-L100"
		license_url = "N/A"
		logic_hash = "aea8afdf118b79f701941ddd4306ee0f1c947ea59de5485ff977beff95e06d35"
		score = 75
		quality = 53
		tags = "BOTNET, LINUXMALWARE, EXPLOITATION, CVE_2019_11581, CVE_2019_10149"
		Author = "Adam M. Swanda"

	strings:
		$py0 = "libpython" ascii
		$str0 = "*/3 * * * * root wget -q -O- https://pastebin.com/raw/" ascii
		$str1 = "*/1 * * * * root curl -fsSL https://pastebin.com/raw/" ascii
		$str6 = "onion.to"
		$str7 = /https?:\/\/pastebin.com\/raw/ nocase
		$str8 = "http://icanhazip.com/"
		$str9 = "http://ident.me/"
		$scan0 = "Scan_run"
		$scan1 = "scan_nexus"
		$scan2 = "scan_couchdb"
		$scan3 = "scan_jenkins"
		$scan4 = "scan_laravel"
		$scan5 = "scan_redis"
		$exploit01 = "CVE_2015_4335"
		$exploit02 = "CVE_2018_1000861"
		$exploit03 = "CVE_2018_8007"
		$exploit04 = "CVE_2019_1014"
		$exploit05 = "CVE_2019_11581"
		$exploit06 = "CVE_2019_7238"
		$pwn0 = "pwn_couchdb"
		$pwn1 = "pwn_jenkins"
		$pwn2 = "pwn_jira"
		$pwn3 = "pwn_nexus"
		$pwn4 = "pwn_redis"
		$pwn5 = "pwn_exim"
		$payload = /payload(s)/ nocase
		$jira_token = "atlassian.xsrf.token=%s" ascii fullword
		$jira_cmd = "set ($cmd=\"%s\")" ascii fullword
		$jira_id = "JSESSIONID=%s" ascii fullword

	condition:
		uint32be( 0x0 ) == 0x7f454c46 and $py0 and ( ( all of ( $pwn* ) and all of ( $scan* ) ) or ( $payload and all of ( $jira* ) and 5 of ( $str* ) ) or ( all of ( $str* ) and all of ( $exploit* ) ) )
}

rule SIGNATURE_BASE_APT_Sandworm_Keywords_May20_1 : CVE_2019_10149 FILE
{
	meta:
		description = "Detects commands used by Sandworm group to exploit critical vulernability CVE-2019-10149 in Exim"
		author = "Florian Roth (Nextron Systems)"
		id = "e0d4e90e-5547-5487-8d0c-a141d88fff7c"
		date = "2020-05-28"
		modified = "2023-12-05"
		reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_sandworm_exim_expl.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "9f9a81ff0c576f05ac063eaca7a5882dbdb09c9a0778610cca2864636a00efce"
		score = 75
		quality = 85
		tags = "CVE-2019-10149, FILE"

	strings:
		$x1 = "MAIL FROM:<$(run("
		$x2 = "exec\\x20\\x2Fusr\\x2Fbin\\x2Fwget\\x20\\x2DO\\x20\\x2D\\x20http"

	condition:
		filesize < 8000KB and 1 of them
}

