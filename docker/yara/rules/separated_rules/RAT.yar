rule TRELLIX_ARC_Poison_Ivy_Softcell : RAT FILE
{
	meta:
		description = "Rule to detect Poison Ivy used in the SoftCell operation"
		author = "Marc Rivero | McAfee ATR Team"
		id = "c362b116-4cb6-5393-9c64-28e8d2886dc7"
		date = "2019-06-25"
		modified = "2020-08-14"
		reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/APT/APT_Operation_SoftCell.yar#L34-L72"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/1919562a59f190bda60c982424f6a24c542ee3e0/LICENSE"
		logic_hash = "ac84023404d76adf8cfd8d26bb59fb51f29057748806c4f5ea0634803fd937cd"
		score = 75
		quality = 70
		tags = "RAT, FILE"
		rule_version = "v1"
		malware_type = "rat"
		malware_family = "Rat:W32/PoisonIvy"
		actor_type = "Apt"
		actor_group = "Unknown"

	strings:
		$s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
		$s2 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
		$s3 = "&Enter password for the encrypted file:" fullword wide
		$s4 = "start \"\" \"%CD%\\mcoemcpy.exe\"" fullword ascii
		$s5 = "setup.bat" fullword ascii
		$s6 = "ErroraErrors encountered while performing the operation" fullword wide
		$s7 = "Please download a fresh copy and retry the installation" fullword wide
		$s8 = "antivir.dat" fullword ascii
		$s9 = "The required volume is absent2The archive is either in unknown format or damaged" fullword wide
		$s10 = "=Total path and file name length must not exceed %d characters" fullword wide
		$s11 = "Please close all applications, reboot Windows and restart this installation\\Some installation files are corrupt." fullword wide
		$op0 = { e8 6f 12 00 00 84 c0 74 04 32 c0 eb 34 56 ff 75 }
		$op1 = { 53 68 b0 34 41 00 57 e8 61 44 00 00 57 e8 31 44 }
		$op2 = { 56 ff 75 08 8d b5 f4 ef ff ff e8 17 ff ff ff 8d }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and ( pe.imphash ( ) == "dbb1eb5c3476069287a73206929932fd" and all of them )
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

