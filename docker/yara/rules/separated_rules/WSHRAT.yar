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

