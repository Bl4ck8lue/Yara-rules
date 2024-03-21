rule learn_yara_qwe {
    meta:
        author="ilya"
        description="Check data on qwe"
    strings:
	    $a={4D 5A 90 00 03 00 00 00}
    condition:
	    $a
}
