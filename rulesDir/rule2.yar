rule learn_yara_lmn {
    meta:
        author="ilya"
        description="Check data on lmn"
    strings:
	    $a={65 74 43 75 72 72 65 6E 74 50 72 6F 63 65 73 55}
    condition:
	    $a
}