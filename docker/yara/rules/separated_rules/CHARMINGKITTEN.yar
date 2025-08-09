rule VOLEXITY_Apt_Win_Powerstar_Persistence_Batch : CHARMINGKITTEN
{
	meta:
		description = "Detects the batch script used to persist PowerStar via Startup."
		author = "threatintel@volexity.com"
		id = "f3ed7b46-d80d-55b1-b6c7-6ea6569f199c"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L1-L19"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "9c3a45b759516959eae1cdf8e73bf540b682c90359a6232aa4782a8d1fe15b7d"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		hash1 = "9777f106ac62829cd3cfdbc156100fe892cfc4038f4c29a076e623dc40a60872"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s_1 = "e^c^h^o o^f^f"
		$s_2 = "powershertxdll.ertxdxe"
		$s_3 = "Get-Conrtxdtent -Prtxdath"
		$s_4 = "%appdata%\\Microsrtxdoft\\Windortxdws\\"
		$s_5 = "&(gcm i*x)$"

	condition:
		3 of them
}

rule VOLEXITY_Apt_Win_Powerstar_Logmessage : CHARMINGKITTEN
{
	meta:
		description = "Detects interesting log message embedded in memory only version of PowerStar."
		author = "threatintel@volexity.com"
		id = "5979c776-5138-50e2-adab-0793ad86ba76"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L66-L79"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "539c9a8b3de24f2c8058d204900344756a8031822ebebc312612b8fb8422e341"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s_1 = "wau, ije ulineun mueos-eul halkkayo?"

	condition:
		all of them
}

rule VOLEXITY_Apt_Win_Powerstar_Lnk : CHARMINGKITTEN
{
	meta:
		description = "Detects LNK command line used to install PowerStar."
		author = "threatintel@volexity.com"
		id = "33f16283-69b9-5109-b723-3ddc8abb8c41"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L80-L97"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "da53aeaf69e80f697068779f4741b8c23cff82dd1bfb0640916a1bcc98c4892f"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$p_1 = "-UseBasicParsing).Content; &(gcm i*x)$"
		$c_1 = "powershecde43ell.ecde43exe"
		$c_2 = "wgcde43eet -Ucde43eri"
		$c_3 = "-UseBasicde43ecParsing).Contcde43eent; &(gcm i*x)$"

	condition:
		any of them
}

rule VOLEXITY_Apt_Win_Powerstar : CHARMINGKITTEN
{
	meta:
		description = "Custom PowerShell backdoor used by Charming Kitten."
		author = "threatintel@volexity.com"
		id = "febcd23b-6545-571b-905d-18dffe8e913f"
		date = "2021-10-13"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L122-L150"
		license_url = "https://github.com/volexity/threat-intel/blob/1ef34c2e4704d1e6e6768c2d6800863bbae05a0d/LICENSE.txt"
		logic_hash = "2cbf59eaee60a8f84b1ac35cec3b01592a2a0f56c92a2db218bb26a15be24bf3"
		score = 75
		quality = 80
		tags = "CHARMINGKITTEN"
		hash1 = "de99c4fa14d99af791826a170b57a70b8265fee61c6b6278d3fe0aad98e85460"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$appname = "[AppProject.Program]::Main()" ascii wide
		$langfilters1 = "*shar*" ascii wide
		$langfilters2 = "*owers*" ascii wide
		$definitions1 = "[string]$language" ascii wide
		$definitions2 = "[string]$Command" ascii wide
		$definitions3 = "[string]$ThreadName" ascii wide
		$definitions4 = "[string]$StartStop" ascii wide
		$sess = "$session = $v + \";;\" + $env:COMPUTERNAME + $mac;" ascii wide

	condition:
		$appname or all of ( $langfilters* ) or all of ( $definitions* ) or $sess
}

