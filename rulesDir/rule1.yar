rule learn_yara_qwe {
    meta:
        author="ilya"
        description="Check data on qwe"
    strings:
	    $a={47 65 74 46 75 6C 6C 50 61 74 68 4E 61 6D 65}
    condition:
	    $a
}
