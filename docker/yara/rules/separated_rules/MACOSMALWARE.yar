rule DEADBITS_Crescentcore_DMG : INSTALLER MACOSMALWARE FILE
{
	meta:
		description = "No description has been set in the source file - DeadBits"
		author = "Adam Swanda"
		id = "2bd03287-3f10-50b0-9560-4c88644f5b20"
		date = "2019-07-18"
		modified = "2019-07-22"
		reference = "https://github.com/deadbits/yara-rules"
		source_url = "https://github.com/deadbits/yara-rules//blob/d002f7ecee23e09142a3ac3e79c84f71dda3f001/rules/crescentcore_dmg.yara#L1-L48"
		license_url = "N/A"
		logic_hash = "819f01fdacea1e95f0f4d4f8e59ebae97ff9489a1be2c60e33253580a8f9e418"
		score = 75
		quality = 26
		tags = "INSTALLER, MACOSMALWARE, FILE"
		Author = "Adam M. Swanda"

	strings:
		$header0 = "__PAGEZERO" ascii
		$header1 = "__TEXT" ascii
		$path0 = "/Users/mehdi/Desktop/RED MOON/Project/WaningCrescent/WaningCrescent/" ascii
		$install0 = ".app\" /Applications" ascii fullword
		$install1 = "open \"/Applications/" ascii fullword
		$str1 = /Flash_Player\dVirusMp/ ascii
		$str2 = /Flash_Player\dAntivirus33/ ascii
		$str3 = /Flash_Player\d{2}Armageddon/ ascii
		$str4 = /Flash_Player\d{2}Armageddon\w\dapocalypsyy/
		$str5 = /Flash_Player\d{2}Armageddon\w\ddoomsdayyy/
		$str6 = /SearchModel\w\dbrowser/
		$str8 = /SearchModel\w\dcountry/
		$str9 = /SearchModel\w\dhomepage/
		$str10 = /SearchModel\w\dthankyou/
		$str11 = /SearchModel\w\dinterrupt/
		$str12 = /SearchModel\w\dsearch/
		$str13 = /SearchModel\w\dsuccess/
		$str14 = /SearchModel\w\d{2}carrierURL/

	condition:
		( uint32( 0 ) == 0xfeedface or uint32( 0 ) == 0xcefaedfe or uint32( 0 ) == 0xfeedfacf or uint32( 0 ) == 0xcffaedfe or uint32( 0 ) == 0xbebafeca ) and $header0 and $header1 and ( ( $path0 and ( any of ( $install* ) ) ) or ( 5 of ( $str* ) ) ) or all of them
}

