rule SIGNATURE_BASE_EXPL_Cleo_Exploitation_Log_Indicators_Dec24 : SCRIPT
{
	meta:
		description = "Detects indicators found in logs during and after Cleo software exploitation (as reported by Huntress in December 2024)"
		author = "Florian Roth"
		id = "385042a9-fc8c-5b50-975f-3436a16e6861"
		date = "2024-12-10"
		modified = "2024-12-12"
		reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cleo_dec24.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "a7e6713a08d7cce00cffba8daa12b251ccc12dc8d5a5f38d568bd5054e3783a2"
		score = 75
		quality = 85
		tags = "SCRIPT"

	strings:
		$x1 = "Note: Processing autorun file 'autorun\\health" ascii wide
		$x2 = "60282967-dc91-40ef-a34c-38e992509c2c.xml" ascii wide
		$x3 = "<Detail level=\"1\">Executing 'cmd.exe /c \"powershell -NonInteractive -EncodedCommand " ascii wide

	condition:
		1 of them
}

rule SIGNATURE_BASE_EXPL_Cleo_Exploitation_PS1_Indicators_Dec24 : SCRIPT
{
	meta:
		description = "Detects encoded and decoded PowerShell loader used during Cleo software exploitation (as reported by Huntress in December 2024)"
		author = "Florian Roth"
		id = "491cda57-0ad0-5ddc-90cb-48411eef2f2e"
		date = "2024-12-10"
		modified = "2024-12-12"
		reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cleo_dec24.yar#L185-L202"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "87dcd0aa3c16d8948514b1d8589d38c6cc73bf7e6262f4517659cead16fedd3d"
		score = 75
		quality = 85
		tags = "SCRIPT"

	strings:
		$xe1 = "Start-Process -WindowStyle Hidden -FilePath jre\\bin\\java.exe" base64 ascii wide
		$xe2 = "$f=\"cleo." base64 ascii wide
		$xe3 = "<Detail level=\"1\">Executing 'cmd.exe /c \"powershell -NonInteractive -EncodedCommand " base64 ascii wide
		$x1 = "$f=\"cleo." ascii wide
		$x2 = "<Detail level=\"1\">Executing 'cmd.exe /c \"powershell -NonInteractive -EncodedCommand " ascii wide

	condition:
		1 of them
}

rule SIGNATURE_BASE_SUSP_ENV_Folder_Root_File_Jan23_1 : SCRIPT FILE
{
	meta:
		description = "Detects suspicious file path pointing to the root of a folder easily accessible via environment variables"
		author = "Florian Roth (Nextron Systems)"
		id = "6067d822-5c1b-5b86-863c-fdcfa37da665"
		date = "2023-01-11"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/gen_susp_indicators.yar#L3-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "5355ae567e6255e22f566bae9fe50f4995bafba07c261461d37d5b8ba200d33a"
		score = 70
		quality = 58
		tags = "SCRIPT, FILE"

	strings:
		$xr1 = /%([Aa]pp[Dd]ata|APPDATA)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii
		$xr2 = /%([Pp]ublic|PUBLIC)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii
		$xr4 = /%([Pp]rogram[Dd]ata|PROGRAMDATA)%\\[A-Za-z0-9_\-]{1,20}\.[a-zA-Z0-9]{1,4}[^\\]/ wide ascii
		$fp1 = "perl -MCPAN " ascii
		$fp2 = "CCleaner" ascii

	condition:
		filesize < 20MB and 1 of ( $x* ) and not 1 of ( $fp* ) and not pe.number_of_signatures > 0
}

rule SIGNATURE_BASE_APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1 : SCRIPT CVE_2023_2868
{
	meta:
		description = "Detects forensic artifacts found in the exploitation of CVE-2023-2868 in Barracuda ESG devices by UNC4841"
		author = "Florian Roth"
		id = "50518fa1-33de-5fe5-b957-904d976fb29a"
		date = "2023-06-15"
		modified = "2023-06-16"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_barracuda_esg_unc4841_jun23.yar#L2-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "fa7cac1e0f6cb6fa3ac271c1fff0039ff182b6859920b4eca25541457654acde"
		score = 75
		quality = 85
		tags = "SCRIPT, CVE-2023-2868"

	strings:
		$x01 = "=;ee=ba;G=s;_ech_o $abcdefg_${ee}se64" ascii
		$x02 = ";echo $abcdefg | base64 -d | sh" ascii
		$x03 = "setsid sh -c \"mkfifo /tmp/p" ascii
		$x04 = "sh -i </tmp/p 2>&1" ascii
		$x05 = "if string.match(hdr:body(), \"^[%w%+/=" ascii
		$x06 = "setsid sh -c \"/sbin/BarracudaMailService eth0\""
		$x07 = "echo \"set the bvp ok\""
		$x08 = "find ${path} -type f ! -name $excludeFileNameKeyword | while read line ;"
		$x09 = " /mail/mstore | xargs -i cp {} /usr/share/.uc/"
		$x10 = "tar -T /mail/mstore/tmplist -czvf "
		$sa1 = "sh -c wget --no-check-certificate http"
		$sa2 = ".tar;chmod +x "

	condition:
		1 of ( $x* ) or all of ( $sa* )
}

rule SIGNATURE_BASE_SUSP_Fscan_Port_Scanner_Output_Jun23 : SCRIPT FILE
{
	meta:
		description = "Detects output generated by the command line port scanner FScan"
		author = "Florian Roth"
		id = "7eb4b27f-0c5b-5d7e-b759-95d7894d5822"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_barracuda_esg_unc4841_jun23.yar#L103-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "49b5055c96d7b7446ee5ae8667a5aa3645f0f98d8b5f2bffcd6ef3b20bc64e05"
		score = 70
		quality = 85
		tags = "SCRIPT, FILE"

	strings:
		$s1 = "[*] NetInfo:" ascii
		$s2 = ":443 open" ascii
		$s3 = "   [->]"

	condition:
		filesize < 800KB and all of them
}

rule SIGNATURE_BASE_SUSP_PY_Shell_Spawn_Jun23_1 : SCRIPT
{
	meta:
		description = "Detects suspicious one-liner to spawn a shell using Python"
		author = "Florian Roth"
		id = "15fd2c9a-c425-5d4d-9209-fd3826074d6c"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/apt_barracuda_esg_unc4841_jun23.yar#L119-L131"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "63e94447930d5a00399de753076facbfb2bf18dd8c815f01aaefd14678aea034"
		score = 70
		quality = 85
		tags = "SCRIPT"

	strings:
		$x1 = "python -c import pty;pty.spawn(\"/bin/" ascii

	condition:
		1 of them
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

rule SIGNATURE_BASE_PUA_Crypto_Mining_Commandline_Indicators_Oct21 : SCRIPT FILE
{
	meta:
		description = "Detects command line parameters often used by crypto mining software"
		author = "Florian Roth (Nextron Systems)"
		id = "afe5a63a-08c3-5cb7-b4b1-b996068124b7"
		date = "2021-10-24"
		modified = "2023-12-05"
		reference = "https://www.poolwatch.io/coin/monero"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/pua_cryptocoin_miner.yar#L54-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "7ae1a77d8ff02ec539ce2b8be668530c3f509f0c408dfa7f2b749b0a4d6f45b7"
		score = 65
		quality = 85
		tags = "SCRIPT, FILE"

	strings:
		$s01 = " --cpu-priority="
		$s02 = "--donate-level=0"
		$s03 = " -o pool."
		$s04 = " -o stratum+tcp://"
		$s05 = " --nicehash"
		$s06 = " --algo=rx/0 "
		$se1 = "LS1kb25hdGUtbGV2ZWw9"
		$se2 = "0tZG9uYXRlLWxldmVsP"
		$se3 = "tLWRvbmF0ZS1sZXZlbD"
		$se4 = "c3RyYXR1bSt0Y3A6Ly"
		$se5 = "N0cmF0dW0rdGNwOi8v"
		$se6 = "zdHJhdHVtK3RjcDovL"
		$se7 = "c3RyYXR1bSt1ZHA6Ly"
		$se8 = "N0cmF0dW0rdWRwOi8v"
		$se9 = "zdHJhdHVtK3VkcDovL"

	condition:
		filesize < 5000KB and 1 of them
}

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

rule SIGNATURE_BASE_SUSP_LNX_Base64_Download_Exec_Apr24 : SCRIPT
{
	meta:
		description = "Detects suspicious base64 encoded shell commands used for downloading and executing further stages"
		author = "Paul Hager"
		id = "df8dddef-3c49-500c-abc8-7f7de5aa69ae"
		date = "2024-04-18"
		modified = "2025-03-21"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/vuln_paloalto_cve_2024_3400_apr24.yar#L48-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "90b7781812b4078550b0d66ba020b3bb0a8217f2de03492af98db6c619f31929"
		score = 75
		quality = 85
		tags = "SCRIPT"

	strings:
		$sa1 = "curl http" base64
		$sa2 = "wget http" base64
		$sb1 = "chmod 777 " base64
		$sb2 = "/tmp/" base64

	condition:
		1 of ( $sa* ) and all of ( $sb* )
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

rule SIGNATURE_BASE_EXPL_Exchange_Proxyshell_Failed_Aug21_1 : SCRIPT
{
	meta:
		description = "Detects ProxyShell exploitation attempts in log files"
		author = "Florian Roth (Nextron Systems)"
		id = "9b849042-8918-5322-a35a-2165d4b541d5"
		date = "2021-08-08"
		modified = "2021-08-09"
		reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_proxyshell.yar#L2-L16"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "690e74633ac8671727fe47f6398e536c1b7a4ac469d27d3f7507c75e175716bd"
		score = 50
		quality = 60
		tags = "SCRIPT"

	strings:
		$xr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|mapi\/nspi|EWS\/|X-Rps-CAT)[^\n]{1,400}401 0 0/ nocase ascii
		$xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}401 0 0/ nocase ascii

	condition:
		1 of them
}

rule SIGNATURE_BASE_EXPL_Exchange_Proxyshell_Successful_Aug21_1 : SCRIPT
{
	meta:
		description = "Detects successful ProxyShell exploitation attempts in log files"
		author = "Florian Roth (Nextron Systems)"
		id = "8c11cd1a-6d3f-5f29-af61-17179b01ca8b"
		date = "2021-08-08"
		modified = "2025-03-21"
		reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_proxyshell.yar#L18-L34"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "06ab609a8efe3b36b6356a9cf7b7b11b2fc2a556ec1df6995008a9df86b3fcee"
		score = 65
		quality = 83
		tags = "SCRIPT"

	strings:
		$xr1a = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|X-Rps-CAT)/ nocase ascii
		$xr1b = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(mapi\/nspi|EWS\/)[^\n]{1,400}(200|302) 0 0/
		$xr2 = /autodiscover\/autodiscover\.json[^\n]{1,60}&X-Rps-CAT=/ nocase ascii
		$xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}200 0 0/ nocase ascii

	condition:
		1 of them
}

rule SIGNATURE_BASE_APT_SAP_Netweaver_Exploitation_Activity_Apr25_1 : SCRIPT CVE_2025_31324 FILE
{
	meta:
		description = "Detects forensic artefacts related to exploitation activity of SAP NetWeaver CVE-2025-31324"
		author = "Florian Roth"
		id = "78863492-5c83-55a8-900b-057e99125414"
		date = "2025-04-25"
		modified = "2025-05-15"
		reference = "https://reliaquest.com/blog/threat-spotlight-reliaquest-uncovers-vulnerability-behind-sap-netweaver-compromise/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_sap_netweaver_apr25.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "ab6c5e17bba15a3f968bdbe88a8cf4a039c55b6035d91fd3c6b30092be89af5c"
		score = 70
		quality = 85
		tags = "SCRIPT, CVE-2025-31324, FILE"

	strings:
		$x01 = "/helper.jsp?cmd=" ascii wide
		$x02 = "/cache.jsp?cmd=" ascii wide

	condition:
		filesize < 20MB and 1 of them
}

rule SIGNATURE_BASE_APT_SAP_Netweaver_Exploitation_Activity_Apr25_2 : SCRIPT CVE_2025_31324 FILE
{
	meta:
		description = "Detects forensic artefacts related to exploitation activity of SAP NetWeaver CVE-2025-31324"
		author = "Florian Roth"
		id = "17fb236e-e78c-51e5-b0a8-14964e38dfc5"
		date = "2025-04-25"
		modified = "2025-05-15"
		reference = "https://reliaquest.com/blog/threat-spotlight-reliaquest-uncovers-vulnerability-behind-sap-netweaver-compromise/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_sap_netweaver_apr25.yar#L16-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "dfc24a4f359e2bc899ab3924bd342c2c6bd8c757b7c1d3859a47f61b9e4039a9"
		score = 70
		quality = 85
		tags = "SCRIPT, CVE-2025-31324, FILE"

	strings:
		$x03 = "MSBuild.exe c:\\programdata\\" ascii wide

	condition:
		filesize < 20MB and 1 of them
}

rule SIGNATURE_BASE_APT_PS1_Sysaid_EXPL_Forensicartifacts_Nov23_1 : SCRIPT CVE_2023_47246
{
	meta:
		description = "Detects forensic artifacts found in attacks on SysAid on-prem software exploiting CVE-2023-47246"
		author = "Florian Roth"
		id = "df7997d3-9309-58b3-8cd7-de9fea36d3c7"
		date = "2023-11-09"
		modified = "2023-12-05"
		reference = "https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_sysaid_cve_2023_47246.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "85efeea88961ca99b22004726d88efc46c748273b9a0b3be674f4cbb12cd3dd1"
		score = 85
		quality = 85
		tags = "SCRIPT, CVE-2023-47246"

	strings:
		$x1 = "if ($s -match '^(Sophos).*\\.exe\\s') {echo $s; $bp++;}" ascii wide
		$x2 = "$s=$env:SehCore;$env:SehCore=\"\";Invoke-Expression $s;" ascii wide

	condition:
		1 of them
}

rule SIGNATURE_BASE_EXPL_Exchange_Proxynotshell_Patterns_CVE_2022_41040_Oct22_1 : SCRIPT
{
	meta:
		description = "Detects successful ProxyNotShell exploitation attempts in log files (attempt to identify the attack before the official release of detailed information)"
		author = "Florian Roth (Nextron Systems)"
		id = "d2812fcd-0a20-5bbd-a9e1-9cca1ed58aa3"
		date = "2022-10-11"
		modified = "2023-03-15"
		old_rule_name = "EXPL_Exchange_ProxyNoShell_Patterns_CVE_2022_41040_Oct22_1"
		reference = "https://github.com/kljunowsky/CVE-2022-41040-POC"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_cve_2022_41040_proxynoshell.yar#L2-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "81b0f0fea2762beb47826ff95545c87e960e098b9d5f45eacfe07b3ecf319ac5"
		score = 75
		quality = 60
		tags = "SCRIPT"

	strings:
		$sr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}owershell/ nocase ascii
		$sa1 = " 200 "
		$fp1 = " 444 "
		$fp2 = " 404 "
		$fp2b = " 401 "
		$fp3 = "GET /owa/ &Email=autodiscover/autodiscover.json%3F@test.com&ClientId=" ascii
		$fp4 = "@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com" ascii

	condition:
		$sr1 and 1 of ( $sa* ) and not 1 of ( $fp* )
}

rule SIGNATURE_BASE_SUSP_Command_Line_Combos_Feb24_2 : SCRIPT FILE
{
	meta:
		description = "Detects suspicious command line combinations often found in post exploitation activities"
		author = "Florian Roth"
		id = "d9bc6083-c3ca-5639-a9df-483fea6d0187"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L105-L118"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "0cd7b4771aa8fd622e873c5cdc6689d24394e5faf026b36d5f228ac09f4e0441"
		score = 75
		quality = 85
		tags = "SCRIPT, FILE"

	strings:
		$sa1 = " | iex"
		$sa2 = "iwr -UseBasicParsing "

	condition:
		filesize < 2MB and all of them
}

rule SIGNATURE_BASE_SUSP_PS1_Combo_Transfersh_Feb24 : SCRIPT
{
	meta:
		description = "Detects suspicious PowerShell command that downloads content from transfer.sh as often found in loaders"
		author = "Florian Roth"
		id = "fd14cca5-9cf8-540b-9d6e-39ca2c267272"
		date = "2024-02-23"
		modified = "2024-04-24"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L120-L135"
		license_url = "https://github.com/Neo23x0/signature-base/blob/a065133ff5763435e4e9e0f6bc72344c44b1824f/LICENSE"
		logic_hash = "64d4343ecdcbc4a28571557bec2f31c1ff73c2ecf63d0feaa0a71001bb9bf499"
		score = 70
		quality = 85
		tags = "SCRIPT"

	strings:
		$x1 = ".DownloadString('https://transfer.sh"
		$x2 = ".DownloadString(\"https://transfer.sh"
		$x3 = "Invoke-WebRequest -Uri 'https://transfer.sh"
		$x4 = "Invoke-WebRequest -Uri \"https://transfer.sh"

	condition:
		1 of them
}

