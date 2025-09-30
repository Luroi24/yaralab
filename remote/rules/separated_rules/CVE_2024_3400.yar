rule SIGNATURE_BASE_APT_UTA028_Forensicartefacts_Paloalto_CVE_2024_3400_Apr24_1 : SCRIPT CVE_2024_3400
{
	meta:
		description = "Detects forensic artefacts of APT UTA028 as found in a campaign exploiting the Palo Alto CVE-2024-3400 vulnerability"
		author = "Florian Roth"
		id = "32cf18ff-784d-5849-87f8-14ede7315188"
		date = "2024-04-15"
		modified = "2024-04-18"
		reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/vuln_paloalto_cve_2024_3400_apr24.yar#L2-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "1261eecca520daa0619859a45d2289d2c23c73be55e1a3849d2032a38e137f4d"
		score = 70
		quality = 85
		tags = "SCRIPT, CVE-2024-3400"

	strings:
		$x1 = "cmd = base64.b64decode(rst.group"
		$x2 = "f.write(\"/*\"+output+\"*/\")"
		$x3 = "* * * * * root wget -qO- http://"
		$x4 = "rm -f /var/appweb/sslvpndocs/global-protect/*.css"
		$x5a = "failed to unmarshal session(../"
		$x5b = "failed to unmarshal session(./../"
		$x6 = "rm -rf /opt/panlogs/tmp/device_telemetry/minute/*" base64
		$x7 = "$(uname -a) > /var/" base64

	condition:
		1 of them
}

rule SIGNATURE_BASE_EXPL_Paloalto_CVE_2024_3400_Apr24_1 : CVE_2024_3400
{
	meta:
		description = "Detects characteristics of the exploit code used in attacks against Palo Alto GlobalProtect CVE-2024-3400"
		author = "Florian Roth"
		id = "1bcf0415-5351-5e09-ab93-496e8dc47c92"
		date = "2024-04-15"
		modified = "2025-03-21"
		reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/vuln_paloalto_cve_2024_3400_apr24.yar#L27-L46"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "9ebc94a07b189a2d2dd252b5079fa494162739678fd2ca742e6877189a140da9"
		score = 70
		quality = 85
		tags = "CVE-2024-3400"

	strings:
		$x1 = "SESSID=../../../../opt/panlogs/"
		$x2 = "SESSID=./../../../../opt/panlogs/"
		$sa1 = "SESSID=../../../../"
		$sa2 = "SESSID=./../../../../"
		$sb2 = "${IFS}"

	condition:
		1 of ( $x* ) or ( 1 of ( $sa* ) and $sb2 )
}

rule SIGNATURE_BASE_SUSP_LNX_Base64_Exec_Apr24 : SCRIPT CVE_2024_3400 FILE
{
	meta:
		description = "Detects suspicious base64 encoded shell commands (as seen in Palo Alto CVE-2024-3400 exploitation)"
		author = "Christian Burkard"
		id = "2da3d050-86b0-5903-97eb-c5f39ce4f3a3"
		date = "2024-04-18"
		modified = "2025-03-21"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/vuln_paloalto_cve_2024_3400_apr24.yar#L81-L105"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "e96fb7c8faac12c1f0210689f2b3a7903b42a543b97ddff11298e5ae13cae80b"
		score = 75
		quality = 85
		tags = "SCRIPT, CVE-2024-3400, FILE"

	strings:
		$s1 = "curl http://" base64
		$s2 = "wget http://" base64
		$s3 = ";chmod 777 " base64
		$mirai = "country="
		$fp1 = "<html"
		$fp2 = "<?xml"

	condition:
		filesize < 800KB and 1 of ( $s* ) and not $mirai and not 1 of ( $fp* )
}

