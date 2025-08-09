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

