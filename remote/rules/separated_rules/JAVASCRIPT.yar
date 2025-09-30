rule SECUINFRA_DROPPER_Valyria_Stage_1 : JAVASCRIPT VBS VALYRIA FILE
{
	meta:
		description = "Family was taken from VirusTotal"
		author = "SECUINFRA Falcon Team"
		id = "7e2ab9db-142c-5dee-92b7-4a70d747c540"
		date = "2022-02-18"
		modified = "2022-02-18"
		reference = "https://bazaar.abuse.ch/sample/c8a8fea3cbe08cd97e56a0e0dbc59a892f8ab1ff3b5217ca3c9b326eeee6ca66/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/valyria.yar#L1-L23"
		license_url = "N/A"
		logic_hash = "94643123a4be26c818d43a77b907edf8651d306463f4df750db67cef790f10eb"
		score = 75
		quality = 70
		tags = "JAVASCRIPT, VBS, VALYRIA, FILE"

	strings:
		$a1 = "<script language=\"vbscript\">"
		$a2 = "<script language=\"javascript\">"
		$b1 = "window.resizeTo(0,0);"
		$b2 = ".Environment"
		$b3 = ".item().Name"
		$b4 = "v4.0.30319"
		$b5 = "v2.0.50727"
		$c1 = "Content Writing.docx"
		$c2 = "eval"

	condition:
		filesize < 600KB and all of ( $a* ) and 3 of ( $b* ) and 1 of ( $c* )
}

rule SECUINFRA_MAL_Agenttesla_Stage_1 : JAVASCRIPT AGENTTESLA OBFUSCATORIO FILE
{
	meta:
		description = "Detects the first stage of AgentTesla (JavaScript)"
		author = "SECUINFRA Falcon Team"
		id = "0a098f27-8dbc-5749-9a0d-fd0198184c7a"
		date = "2022-02-27"
		modified = "2022-02-27"
		reference = "https://bazaar.abuse.ch/sample/bd257d674778100639b298ea35550bf3bcb8b518978c502453e9839846f9bbec/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/agent_tesla.yar#L1-L18"
		license_url = "N/A"
		hash = "bd257d674778100639b298ea35550bf3bcb8b518978c502453e9839846f9bbec"
		logic_hash = "7c21f80a02aa161ffb2edf47aff796f22aff2a563abcb0097cc86371c05e516d"
		score = 75
		quality = 45
		tags = "JAVASCRIPT, AGENTTESLA, OBFUSCATORIO, FILE"

	strings:
		$mz = "TVq"
		$a1 = ".jar"
		$a2 = "bin.base64"
		$a3 = "appdata"
		$a4 = "skype.exe"

	condition:
		filesize < 500KB and $mz and 3 of ( $a* )
}

rule SECUINFRA_DROPPER_Vjw0Rm_Stage_1 : JAVASCRIPT DROPPER VJW0RM FILE
{
	meta:
		description = "No description has been set in the source file - SecuInfra"
		author = "SECUINFRA Falcon Team"
		id = "a07f80e4-56c3-5b75-be64-648bc1fde964"
		date = "2022-02-19"
		modified = "2022-02-27"
		reference = "https://bazaar.abuse.ch/browse.php?search=tag%3AVjw0rm"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/Vjw0rm.yar#L2-L19"
		license_url = "N/A"
		logic_hash = "e5cc23431239e8a650369729050809cf6fe2acc58941086f79ce004b4f506eed"
		score = 75
		quality = 20
		tags = "JAVASCRIPT, DROPPER, VJW0RM, FILE"
		version = "0.1"

	strings:
		$a1 = "$$$"
		$a2 = "microsoft.xmldom"
		$a3 = "eval"
		$a4 = "join(\"\")"

	condition:
		( uint16( 0 ) == 0x7566 or uint16( 0 ) == 0x6176 or uint16( 0 ) == 0x0a0d or uint16( 0 ) == 0x660a ) and filesize < 60KB and all of ( $a* )
}

rule SECUINFRA_MAL_WSHRAT : RAT JAVASCRIPT WSHRAT FILE
{
	meta:
		description = "Detects the final Payload of WSHART"
		author = "SECUINFRA Falcon Team"
		id = "8db5e349-c83e-53c3-a44d-cfe4732fe08d"
		date = "2022-12-02"
		modified = "2022-02-13"
		reference = "https://github.com/SIFalcon/Detection"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/RAT/wshrat.yar#L2-L44"
		license_url = "N/A"
		hash = "b7f53ccc492400290016e802e946e526"
		logic_hash = "12d893f0ca83e805fa570d3f72eb733c8d8b1ae6c0d37bf179ac675d108c7412"
		score = 75
		quality = 68
		tags = "RAT, JAVASCRIPT, WSHRAT, FILE"

	strings:
		$function1 = "runBinder"
		$function2 = "getBinder"
		$function3 = "Base64Encode"
		$function4 = "payloadLuncher"
		$function5 = "getMailRec"
		$function6 = "getHbrowser"
		$function7 = "passgrabber"
		$function8 = "getRDP"
		$function9 = "getUVNC"
		$function10 = "getConfig"
		$function11 = "getKeyLogger"
		$function12 = "enumprocess"
		$function13 = "cmdshell"
		$function14 = "faceMask"
		$function15 = "upload"
		$function16 = "download"
		$function17 = "sitedownloader"
		$function18 = "servicestarter"
		$function19 = "payloadLuncher"
		$function20 = "keyloggerstarter"
		$function21 = "reverserdp"
		$function22 = "reverseproxy"
		$function23 = "decode_pass"
		$function24 = "disableSecurity"
		$function25 = "installsdk"
		$cmd1 = "osversion = eval(osversion)"
		$cmd2 = "download(cmd[1],cmd[2])"
		$cmd3 = "keyloggerstarter(cmd[1]"
		$cmd4 = "decode_pass(retcmd);"

	condition:
		filesize < 2MB and 2 of ( $cmd* ) and 12 of ( $function* )
}

