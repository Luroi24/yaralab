rule DEADBITS_APT32_Ratsnif : APT32 TROJAN WINMALWARE FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "d3664a84-bb53-5715-8b0d-e63f43d62496"
		date = "2019-07-18"
		modified = "2019-08-08"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/APT32_Ratsnif.yara#L1-L65"
		license_url = "N/A"
		logic_hash = "a33eb2bb9ffe02f9b3fe706bd6a611457c669adc24c34f12d9014ed29ba1399f"
		score = 75
		quality = 55
		tags = "APT32, TROJAN, WINMALWARE, FILE"
		Author = "Adam M. Swanda"

	strings:
		$pdb0 = "X:\\Project\\BotFrame\\Debug\\Client.pdb" ascii fullword
		$str1 = "LastIP" ascii fullword
		$str2 = "LastOnline" ascii fullword
		$str3 = "LoaderType" ascii fullword
		$str4 = "Payload" ascii fullword
		$str5 = "PayloadFile" ascii fullword
		$str6 = "ClientCommand" ascii fullword
		$str7 = "ClientId" ascii fullword
		$str8 = "UserAdmin" ascii fullword
		$str9 = "User" ascii fullword
		$str10 = "Password" ascii fullword
		$str11 = "Access" ascii fullword
		$str12 = "CreateDate" ascii fullword
		$str13 = "CreateBy" ascii fullword
		$str14 = "UserName" ascii fullword
		$str15 = "ComputerName" ascii fullword
		$str16 = "Domain" ascii fullword
		$str17 = "OSType" ascii fullword
		$str18 = "OSArch" ascii fullword
		$str19 = "OSVer" ascii fullword
		$str20 = "InstallDate" ascii fullword
		$str21 = "LastLoadCommandID" ascii fullword
		$str22 = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36" ascii fullword
		$str25 = "#########################Program starting up#########################" ascii fullword
		$str26 = "Stop poison" ascii fullword
		$str27 = "Shell:" ascii fullword
		$str28 = "shell" ascii fullword
		$str29 = "Select http redirect domain:" ascii fullword
		$str30 = "HTTP redirect add file extension:" ascii fullword
		$str32 = "exIp" ascii fullword
		$str33 = "Start Poison" ascii fullword
		$str34 = "vicIP" ascii fullword
		$str35 = "Insert JSTag" ascii fullword
		$str36 = "devIp" ascii fullword
		$str37 = "TransmitTcp" ascii fullword
		$str38 = "Remove poison IP: %s" ascii fullword
		$str39 = "Remove my ip or gateway ip: %s" ascii fullword
		$cnc0 = "/cl_client_online.php" ascii fullword
		$cnc1 = "/cl_client_cmd.php" ascii fullword
		$cnc2 = "/cl_client_cmd_res.php" ascii fullword
		$cnc3 = "/cl_client_file_download.php" ascii fullword
		$cnc4 = "/ad_file_download.php" ascii fullword
		$cnc5 = "/cl_client_file_upload.php" ascii fullword
		$cnc6 = "/cl_client_logs.php" ascii fullword

	condition:
		( uint16( 0 ) == 0x5a4d ) and ( ( 10 of ( $str* ) and 3 of ( $cnc* ) ) or ( 3 of ( $cnc* ) and $pdb0 ) )
}

