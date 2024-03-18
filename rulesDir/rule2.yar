rule learn_yara_lmn {
    meta:
        author="ilya"
        description="Check data on lmn"
    strings:
	    $a="lmn"
    condition:
	    $a
}