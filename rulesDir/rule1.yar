rule learn_yara_qwe {
    meta:
        author="ilya"
        description="Check data on qwe"
    strings:
	    $a="lmn"
    condition:
	    $a
}
