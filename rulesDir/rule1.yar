rule learn_yara_qwe {
    meta:
        author="ilya"
        description="Check data on qwe"
    strings:
	    $a={57 69 6C 64}
    condition:
	    $a
}
