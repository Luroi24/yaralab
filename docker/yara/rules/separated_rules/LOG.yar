rule SIGNATURE_BASE_EXPL_LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_1 : LOG CVE_2021_27065
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-27065"
		author = "Florian Roth (Nextron Systems)"
		id = "dcc1f741-cab0-5a0b-a261-a6bd05989723"
		date = "2021-03-02"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hafnium_log_sigs.yar#L2-L13"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "9306cf177928266ea921461e9da80ad5bb37e1e0848559898a414956cfbc2b49"
		score = 75
		quality = 85
		tags = "LOG, CVE-2021-27065"

	strings:
		$s1 = "S:CMD=Set-OabVirtualDirectory.ExternalUrl='" ascii wide fullword

	condition:
		1 of them
}

rule SIGNATURE_BASE_EXPL_LOG_CVE_2021_26858_Exchange_Forensic_Artefacts_Mar21_1 : LOG CVE_2021_26858
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-26858"
		author = "Florian Roth (Nextron Systems)"
		id = "f6fa90c7-c2c0-56db-bf7b-dc146761a995"
		date = "2021-03-02"
		modified = "2021-03-04"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hafnium_log_sigs.yar#L15-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "0a8296b7e990e52330412288e9ff71e08a5258fc63c4754e6d0e6d64302f55e6"
		score = 65
		quality = 60
		tags = "LOG, CVE-2021-26858"

	strings:
		$xr1 = /POST (\/owa\/auth\/Current\/themes\/resources\/logon\.css|\/owa\/auth\/Current\/themes\/resources\/owafont_ja\.css|\/owa\/auth\/Current\/themes\/resources\/lgnbotl\.gif|\/owa\/auth\/Current\/themes\/resources\/owafont_ko\.css|\/owa\/auth\/Current\/themes\/resources\/SegoeUI-SemiBold\.eot|\/owa\/auth\/Current\/themes\/resources\/SegoeUI-SemiLight\.ttf|\/owa\/auth\/Current\/themes\/resources\/lgnbotl\.gif)/

	condition:
		$xr1
}

rule SIGNATURE_BASE_LOG_Exchange_Forensic_Artefacts_Cleanup_Activity_Mar21_1 : LOG
{
	meta:
		description = "Detects forensic artefacts showing cleanup activity found in HAFNIUM intrusions exploiting"
		author = "Florian Roth (Nextron Systems)"
		id = "95b19544-147b-5496-b717-669cbc488179"
		date = "2021-03-08"
		modified = "2023-12-05"
		reference = "https://twitter.com/jdferrell3/status/1368626281970024448"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hafnium_log_sigs.yar#L48-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "12e5b76dafcae13f1eb21913ae0bde233152fd8b9d29f073893418ac9f742de3"
		score = 70
		quality = 85
		tags = "LOG"

	strings:
		$x1 = "cmd.exe /c cd /d C:/inetpub/wwwroot/aspnet_client" ascii wide
		$x2 = "cmd.exe /c cd /d C:\\inetpub\\wwwroot\\aspnet_client" ascii wide
		$s1 = "aspnet_client&del '"
		$s2 = "aspnet_client&attrib +h +s +r "
		$s3 = "&echo [S]"

	condition:
		1 of ( $x* ) or 2 of them
}

rule SIGNATURE_BASE_EXPL_LOG_CVE_2021_27055_Exchange_Forensic_Artefacts : LOG
{
	meta:
		description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
		author = "Zach Stanford - @svch0st, Florian Roth"
		id = "8b0110a9-fd03-5f7d-bdd8-03ff48bcac68"
		date = "2021-03-10"
		modified = "2021-03-15"
		reference = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hafnium_log_sigs.yar#L67-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "131ff0ce189dfeace0922000b0d15dfb5a1270bee8fba8e4d66aa75b1d3f864f"
		score = 65
		quality = 35
		tags = "LOG"

	strings:
		$x1 = "ServerInfo~" ascii wide
		$sr1 = /\/ecp\/[0-9a-zA-Z]{1,3}\.js/ ascii wide
		$s1 = "/ecp/auth/w.js" ascii wide
		$s2 = "/owa/auth/w.js" ascii wide
		$s3 = "/owa/auth/x.js" ascii wide
		$s4 = "/ecp/main.css" ascii wide
		$s5 = "/ecp/default.flt" ascii wide
		$s6 = "/owa/auth/Current/themes/resources/logon.css" ascii wide

	condition:
		$x1 and 1 of ( $s* )
}

rule SIGNATURE_BASE_LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_2 : LOG
{
	meta:
		description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
		author = "Florian Roth (Nextron Systems)"
		id = "37a26def-b360-518e-a4ab-9604a5b39afd"
		date = "2021-03-10"
		modified = "2023-12-05"
		reference = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_hafnium_log_sigs.yar#L92-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "13e2e46689bc0e87c3cf13dc2ce213c384afe6c03c21e62a467974a0518c12da"
		score = 65
		quality = 60
		tags = "LOG"

	strings:
		$sr1 = /GET \/rpc\/ &CorrelationID=<empty>;&RequestId=[^\n]{40,600} (200|301|302)/

	condition:
		$sr1
}

rule SIGNATURE_BASE_LOG_EXPL_Adselfservice_CVE_2021_40539_ADSLOG_Sep21 : LOG CVE_2021_40539 FILE
{
	meta:
		description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
		author = "Florian Roth (Nextron Systems)"
		id = "156317c6-e726-506d-8b07-4f74dae2807f"
		date = "2021-09-20"
		modified = "2023-12-05"
		reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_adselfservice_cve_2021_40539.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "49b7857187c15f48e928747266adca44c227964cef72914616ea269b0e88fe73"
		score = 70
		quality = 85
		tags = "LOG, CVE-2021-40539, FILE"

	strings:
		$x1 = "Java traceback errors that include references to NullPointerException in addSmartCardConfig or getSmartCardConfig" ascii wide

	condition:
		filesize < 50MB and 1 of them
}

rule SIGNATURE_BASE_LOG_EXPL_Adselfservice_CVE_2021_40539_Weblog_Sep21_1 : LOG CVE_2021_40539 FILE
{
	meta:
		description = "Detects suspicious log lines produeced during the exploitation of ADSelfService vulnerability CVE-2021-40539"
		author = "Florian Roth (Nextron Systems)"
		id = "015957a6-8778-5836-af94-6e6d3838f693"
		date = "2021-09-20"
		modified = "2023-12-05"
		reference = "https://us-cert.cisa.gov/ncas/alerts/aa21-259a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_adselfservice_cve_2021_40539.yar#L16-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "bc27afd63d32ac95711e5b4e70764fe0d1bcbb4b4b9b4e3f324e058bba2ef8f6"
		score = 60
		quality = 85
		tags = "LOG, CVE-2021-40539, FILE"

	strings:
		$x1 = "/ServletApi/../RestApi/LogonCustomization" ascii wide
		$x2 = "/ServletApi/../RestAPI/Connection" ascii wide

	condition:
		filesize < 50MB and 1 of them
}

rule SIGNATURE_BASE_LOG_EXPL_Confluence_RCE_CVE_2021_26084_Sep21 : LOG CVE_2021_26084
{
	meta:
		description = "Detects exploitation attempts against Confluence servers abusing a RCE reported as CVE-2021-26084"
		author = "Florian Roth (Nextron Systems)"
		id = "bbf98ce4-d32b-541a-b727-bc35c9aaef53"
		date = "2021-09-01"
		modified = "2023-12-05"
		reference = "https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cve_2021_26084_confluence_log.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "04542570b4814efde3d96ba5be8b5f9fd6e3c51be09f0e8a1c4eba45bfd8f5ff"
		score = 55
		quality = 60
		tags = "LOG, CVE-2021-26084"

	strings:
		$xr1 = /isSafeExpression Unsafe clause found in \['[^\n]{1,64}\\u0027/ ascii wide
		$xs1 = "[util.velocity.debug.DebugReferenceInsertionEventHandler] referenceInsert resolving reference [$!queryString]"
		$xs2 = "userName: anonymous | action: createpage-entervariables ognl.ExpressionSyntaxException: Malformed OGNL expression: '\\' [ognl.TokenMgrError: Lexical error at line 1"
		$sa1 = "GET /pages/doenterpagevariables.action"
		$sb1 = "%5c%75%30%30%32%37"
		$sb2 = "\\u0027"
		$sc1 = " ERROR "
		$sc2 = " | userName: anonymous | action: createpage-entervariables"
		$re1 = /\[confluence\.plugins\.synchrony\.SynchronyContextProvider\] getContextMap (\n )?-- url: \/pages\/createpage-entervariables\.action/

	condition:
		1 of ( $x* ) or ( $sa1 and 1 of ( $sb* ) ) or ( all of ( $sc* ) and $re1 )
}

rule SIGNATURE_BASE_LOG_F5_BIGIP_Exploitation_Artefacts_CVE_2021_22986_Mar21_1 : LOG
{
	meta:
		description = "Detects forensic artefacts indicating successful exploitation of F5 BIG IP appliances as reported by NCCGroup"
		author = "Florian Roth (Nextron Systems)"
		id = "e109ebeb-e5c3-5999-95dc-0963ed8461a6"
		date = "2021-03-20"
		modified = "2023-12-05"
		reference = "https://research.nccgroup.com/2021/03/18/rift-detection-capabilities-for-recent-f5-big-ip-big-iq-icontrol-rest-api-vulnerabilities-cve-2021-22986/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/exploit_f5_bigip_cve_2021_22986_log.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "748bb429d4a086e2890773558ea502ef06f507aed5f0f70470e2cd97a3fd5007"
		score = 80
		quality = 85
		tags = "LOG"

	strings:
		$x1 = "\",\"method\":\"POST\",\"uri\":\"http://localhost:8100/mgmt/tm/util/bash\",\"status\":200," ascii
		$x2 = "[com.f5.rest.app.RestServerServlet] X-F5-Auth-Token doesn't have value, so skipping" ascii

	condition:
		1 of them
}

