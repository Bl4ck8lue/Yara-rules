rule learn_yara_lmn {
    meta:
        author="ilya"
        description="Check data on lmn"
    strings:
	    $a={6A[2]6C7A78637662}
    condition:
	    $a
}