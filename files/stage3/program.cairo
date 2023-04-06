// Function 0
func starkware.cairo.common.hash.hash2{hash_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*}(x : felt, y : felt) -> (result : felt){
    v1_x = [v0_hash_ptr]
    v2_y = [v0_hash_ptr + 1]
    v5 = v0_hash_ptr + 3
    v6 = [v0_hash_ptr + 2]
    return(v6)
}

// Function 1
func starkware.cairo.lang.compiler.lib.registers.get_fp_and_pc{}() -> (fp_val : felt*, pc_val : felt*){
    return(v7_callers_function_frame, v8_return_instruction)
}

// Function 2
@known_ap_change func starkware.cairo.lang.compiler.lib.registers.get_ap{}() -> (ap_val : felt*){
    let (v12_pc_val, v11_fp_val) = get_fp_and_pc()
    v13 = v11_fp_val - 2
    return(v13)
}

// Function 3
@known_ap_change func starkware.cairo.common.math.assert_250_bit{range_check_ptr : felt}(value : felt){
    %{ 
        from starkware.cairo.common.math_utils import as_int
        
        # Correctness check.
        value = as_int(ids.value, PRIME) % PRIME
        assert value < ids.UPPER_BOUND, f'{value} is outside of the range [0, 2**250).'
        
        # Calculation for the assertion.
        ids.high, ids.low = divmod(ids.value, ids.SHIFT)
    %} 
    v18_callers_function_frame = 0x3ffffffffffffffffffffffffffffff    // 0x3ffffffffffffffffffffffffffffff
    v19_return_instruction = [v14_fp_val + 1]
    assert v18_callers_function_frame = v20 + v19_return_instruction
    v20 = [v14_fp_val + 2]
    v21 = [v14_fp_val + 1]
    v22 = v21 * 340282366920938463463374607431768211456
    v23 = [v14_fp_val]
    v15_pc_val = v22 + v23
    v24 = v14_fp_val + 3
    ret
}

// Function 4
@known_ap_change func starkware.starknet.common.storage.normalize_address{range_check_ptr : felt}(addr : felt) -> (res : felt){
    %{ 
        # Verify the assumptions on the relationship between 2**250, ADDR_BOUND and PRIME.
        ADDR_BOUND = ids.ADDR_BOUND % PRIME
        assert (2**250 < ADDR_BOUND <= 2**251) and (2 * 2**250 < PRIME) and (
                ADDR_BOUND * 2 > PRIME), \
            'normalize_address() cannot be used with the current constants.'
        ids.is_small = 1 if ids.addr < ADDR_BOUND else 0
    %} 
    if (v28_return_instruction == 0) {
        v29 = v25_range_check_ptr
        v30 = v26_addr + 106710729501573572985208420194530329073740042555888586719489
        assert_250_bit(v30)
        v31 = -1    // -0x1
        v32 = v30
        assert v31 = v33 + v26_addr
        assert_250_bit(v33)
        v34 = v26_addr + 106710729501573572985208420194530329073740042555888586719489
        return(v34)

    }
    %{ 
        ids.is_250 = 1 if ids.addr < 2**250 else 0
    %} 
    if (v34 == 0) {
        v35 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeff    // 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeff
        v36 = v25_range_check_ptr
        assert v35 = v37 + v26_addr
        assert_250_bit(v37)
    else:
        v38 = v25_range_check_ptr
        v39 = v26_addr
        assert_250_bit(v39)
    }
    v40 = v26_addr
    return(v40)
}

// Function 5
func starkware.starknet.common.syscalls.get_caller_address{syscall_ptr : felt*}() -> (caller_address : felt){
    v44 = 0x47657443616c6c657241646472657373    // 0x47657443616c6c657241646472657373
    assert v44 == [v41_syscall_ptr]
    %{ 
        syscall_handler.get_caller_address(segments=segments, syscall_ptr=ids.syscall_ptr)
    %} 
    v45 = v41_syscall_ptr + 2
    v46 = [v41_syscall_ptr + 1]
    return(v46)
}

// Function 6
func starkware.starknet.common.syscalls.storage_read{syscall_ptr : felt*}(address : felt) -> (value : felt){
    v51 = 0x53746f7261676552656164    // 0x53746f7261676552656164
    assert v51 == [v47_syscall_ptr]
    v48_address = [v47_syscall_ptr + 1]
    %{ 
        syscall_handler.storage_read(segments=segments, syscall_ptr=ids.syscall_ptr)
    %} 
    v52 = v47_syscall_ptr + 3
    v53 = [v47_syscall_ptr + 2]
    return(v53)
}

// Function 7
func starkware.starknet.common.syscalls.storage_write{syscall_ptr : felt*}(address : felt, value : felt){
    v59 = 0x53746f726167655772697465    // 0x53746f726167655772697465
    assert v59 == [v54_syscall_ptr]
    v55_address = [v54_syscall_ptr + 1]
    v56_value = [v54_syscall_ptr + 2]
    %{ 
        syscall_handler.storage_write(segments=segments, syscall_ptr=ids.syscall_ptr)
    %} 
    v60 = v54_syscall_ptr + 3
    ret
}

// Function 8
func __main__.ids.addr{pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(pubkey : felt) -> (res : felt){
    v66 = v61_pedersen_ptr
    v67 = 0x15a59b5fd505b82b3aff0b04f5cdd2ceb73c4478a788ac7a91d4ae213ec3e04    // 0x15a59b5fd505b82b3aff0b04f5cdd2ceb73c4478a788ac7a91d4ae213ec3e04
    v68 = v63_pubkey
    let (v69_result) = hash2(v67, v68)
    v70 = v62_range_check_ptr
    v71 = v69_result
    let (v72_res) = normalize_address(v71)
    v73 = v42_callers_function_frame
    v74 = v71
    v75 = v72_res
    return(v75)
}

// Function 9
func __main__.ids.read{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(pubkey : felt) -> (res : felt){
    v82_callers_function_frame = v77_res
    v83_return_instruction = v78_syscall_ptr
    v84 = v79_pedersen_ptr
    let (v85_res) = addr(v84)
    v86 = v76_result
    v87 = v85_res
    let (v88_value) = storage_read(v87)
    v89 = v87
    v90 = v79_pedersen_ptr
    v91 = v80_range_check_ptr
    v92 = v88_value
    return(v92)
}

// Function 10
func __main__.ids.write{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(pubkey : felt, value : felt){
    v100_callers_function_frame = v94_value
    v101_return_instruction = v95_syscall_ptr
    v102 = v96_pedersen_ptr
    let (v103_res) = addr(v102)
    v104 = v93_res
    v105 = v103_res
    v106 = v97_range_check_ptr
    storage_write(v105, v106)
    v107 = v97_range_check_ptr
    v108 = v98_pubkey
    ret
}

// Function 11
func __main__.owner.addr{pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}() -> (res : felt){
    v113_return_instruction = v109_res
    v114 = v110_pedersen_ptr
    v115 = 0x2016836a56b71f0d02689e69e326f4f4c1b9057164ef592671cf0d37c8040c0    // 0x2016836a56b71f0d02689e69e326f4f4c1b9057164ef592671cf0d37c8040c0
    return(v115)
}

// Function 12
func __main__.owner.read{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}() -> (account : felt){
    v121 = v117_pedersen_ptr
    v122 = v118_range_check_ptr
    let (v123_res) = addr()
    v124 = v116_syscall_ptr
    v125 = v123_res
    let (v126_value) = storage_read(v125)
    v127 = v125
    v128 = v117_pedersen_ptr
    v129 = v118_range_check_ptr
    v130 = v126_value
    return(v130)
}

// Function 13
func __main__.owner.write{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(value : felt){
    v137_callers_function_frame = v132_value
    v138_return_instruction = v133_syscall_ptr
    let (v139_res) = addr()
    v140 = v131_res
    v141 = v139_res
    v142 = v134_pedersen_ptr
    storage_write(v141, v142)
    v143 = v133_syscall_ptr
    v144 = v134_pedersen_ptr
    ret
}

// Function 14
func __main__.nonce.addr{pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}() -> (res : felt){
    v149_return_instruction = v145_res
    v150 = v146_pedersen_ptr
    v151 = 0x2b1577440dd7bedf920cb6de2f9fc6bf7ba98c78c85a3fa1f8311aac95e1759    // 0x2b1577440dd7bedf920cb6de2f9fc6bf7ba98c78c85a3fa1f8311aac95e1759
    return(v151)
}

// Function 15
func __main__.nonce.read{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}() -> (nonce : felt){
    v157 = v153_pedersen_ptr
    v158 = v154_range_check_ptr
    let (v159_res) = addr()
    v160 = v152_syscall_ptr
    v161 = v159_res
    let (v162_value) = storage_read(v161)
    v163 = v161
    v164 = v153_pedersen_ptr
    v165 = v154_range_check_ptr
    v166 = v162_value
    return(v166)
}

// Function 16
func __main__.nonce.write{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(value : felt){
    v173_callers_function_frame = v168_value
    v174_return_instruction = v169_syscall_ptr
    let (v175_res) = addr()
    v176 = v167_res
    v177 = v175_res
    v178 = v170_pedersen_ptr
    storage_write(v177, v178)
    v179 = v169_syscall_ptr
    v180 = v170_pedersen_ptr
    ret
}

// Function 17
@constructor func __main__.constructor{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(_owner : felt, _nonce : felt){
    v188_return_instruction = v181_res
    v189 = v182_syscall_ptr
    v190 = v183_pedersen_ptr
    v191 = v184_range_check_ptr
    write(v191)
    v192 = v185__owner
    write(v192)
    ret
}

// Function 18
@constructor func __wrappers__.constructor{}() -> (syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt, size : felt, retdata : felt*){
    v195 = v192 + 2
    assert v195 = v191 + v192
    v196 = [v190]
    v197 = [v190 + 1]
    v198 = [v190 + 2]
    v199 = [v192]
    v200 = [v192 + 1]
    constructor(v199, v200)
    %{ 
        memory[ap] = segments.add()
    %} 

    v201 = v197
    v202 = v198
    v203 = v199
    v204 = 0    // 0x0
    v205 = v200
    return(v201, v202, v203, v204, v205)
}

// Function 19
func __main__.j{}(id_hash : felt, code : felt*){
    let (v210_ap_val) = get_ap()
    assert v210_ap_val = v210_ap_val + 6
    v211 = [v207_code + 2]
    v212 = 0x480680017fff8000    // 0x480680017fff8000
    v213 = v206_id_hash
    v214 = 0x400680017fff8000    // 0x400680017fff8000
    v215 = [v207_code]
    v216 = 0x48507fff7fff8000    // 0x48507fff7fff8000
    v217 = 0x484480017fff8000    // 0x484480017fff8000
    v218 = 4919    // 0x1337
    v219 = 0x400680017fff8000    // 0x400680017fff8000
    v220 = 4918    // 0x1336
    v221 = 0x484480017fff8000    // 0x484480017fff8000
    v222 = [v207_code + 1]
    v223 = v211 * v213
    call abs [FP]
    ret
}

// Function 20
func __main__._validate{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(id_hash : felt, code : felt*){
    v231_return_instruction = v227_range_check_ptr
    v232 = v228_id_hash
    j(v231_return_instruction, v232)
    v233 = v224_ap_val
    v234 = v225_syscall_ptr
    v235 = v226_pedersen_ptr
    ret
}

// Function 21
func __main__.first{pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*}(curr : felt, in_len : felt, in : felt*) -> (res : felt){
    if (v238_in_len == 0) {
        v242 = v236_pedersen_ptr
        v243 = v237_curr
        return(v243)

    }
    v244 = v236_pedersen_ptr
    v245 = v237_curr
    v246 = [v239_in]
    let (v247_result) = hash2(v245, v246)
    v248 = v238_in_len - 1
    v249 = v239_in + 1
    let (v250_res) = first(v247_result, v248, v249)
    return(v250_res)
}

// Function 22
func __main__.second{range_check_ptr : felt}(h : felt, a : felt, b : felt){
    v253_range_check_ptr = [v251_result]
    v254_h = [v251_result + 1]
    v257_callers_function_frame = 0x1000000000000000000000000000    // 0x1000000000000000000000000000
    assert v257_callers_function_frame = v258_return_instruction + v253_range_check_ptr
    v258_return_instruction = [v251_result + 2]
    v259 = v253_range_check_ptr * 340282366920938463463374607431768211456
    v252_res = v259 + v254_h
    v260 = v251_result + 3
    ret
}

// Function 23
@external func __main__.validate{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(id : felt, code_len : felt, code : felt*, a : felt, b : felt){
    v271 = v261_syscall_ptr
    v272 = v262_pedersen_ptr
    v273 = v263_range_check_ptr
    assert_only_owner()
    v274 = v264_id
    assert_only_once(v274)
    v275 = v264_id
    v276 = 1    // 0x1
    write(v275, v276)
    let (v277_nonce) = read()
    assert v271 = v276
    assert v272 = v277_nonce
    assert v273 = v274
    v278 = v275
    v279 = v272
    v280 = v265_code_len
    v281 = v266_code
    let (v282_res) = first(v279, v280, v281)
    v283 = v271
    v284 = v282_res
    v285 = v267_a
    v286 = v268_b
    second(v284, v285, v286)
    v287 = v275
    v288 = v272
    v289 = v264_id
    let (v290_result) = hash2(v288, v289)
    v265_code_len = [v283]
    v291 = v265_code_len - 3
    assert v291 == [v283 + 1]
    v292 = v273
    v293 = v289
    v294 = v283 + 2
    v295 = v290_result
    v296 = v266_code
    _validate(v295, v296)
    ret
}

// Function 24
@external func __wrappers__.validate{}() -> (syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt, size : felt, retdata : felt*){
    v299_result = [v294 + 2]
    v300_callers_function_frame = [v296 + 1]
    assert v300_callers_function_frame == [v299_result]
    v301_return_instruction = v296 + 2
    v302 = [v296 + 1]
    v303 = v301_return_instruction + v302
    v304 = v303 + 2
    assert v304 = v295 + v296
    v305 = [v294 + 2]
    v306 = [v294]
    v307 = [v294 + 1]
    v308 = v305 + 1
    v309 = [v296]
    v310 = [v296 + 1]
    v311 = v296 + 2
    v312 = [v303]
    v313 = [v303 + 1]
    validate(v309, v310, v311, v312, v313)
    %{ 
        memory[ap] = segments.add()
    %} 

    v314 = v310
    v315 = v311
    v316 = v312
    v317 = 0    // 0x0
    v318 = v313
    return(v314, v315, v316, v317, v318)
}

// Function 25
@view func __main__.get_owner{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}() -> (account : felt){
    v324 = v319_syscall_ptr
    v325 = v320_pedersen_ptr
    v326 = v321_range_check_ptr
    let (v327_account) = read()
    return(v327_account)
}

// Function 26
func __wrappers__.get_owner_encode_return{}(ret_value : (account: felt), range_check_ptr : felt) -> (range_check_ptr : felt, data_len : felt, data : felt*){
    %{ 
        memory[ap] = segments.add()
    %} 

    v328_account = [v332_return_instruction]
    v332_return_instruction = v332_return_instruction + 1
    v333 = v329_ret_value
    assert v332_return_instruction = v334 + v332_return_instruction
    v335 = v332_return_instruction
    return(v333, v334, v335)
}

// Function 27
@view func __wrappers__.get_owner{}() -> (syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt, size : felt, retdata : felt*){
    v335 = v334 + v335
    v338 = [v333]
    v339 = [v333 + 1]
    v340 = [v333 + 2]
    let (v341_account) = get_owner()
    v342 = v340
    let (v345_data, v344_data_len, v343_range_check_ptr) = get_owner_encode_return(v341_account, v342)
    v346 = v334
    v347 = v335
    v348 = v343_range_check_ptr
    v349 = v344_data_len
    v350 = v345_data
    return(v346, v347, v348, v349, v350)
}

// Function 28
func __main__.assert_only_owner{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(){
    v356_pedersen_ptr = v351_account
    v357_range_check_ptr = v352_range_check_ptr
    v358_callers_function_frame = v353_data_len
    let (v359_return_instruction) = read()
    v360_account = v356_pedersen_ptr
    let (v361_caller_address) = get_caller_address()
    v355_syscall_ptr = v361_caller_address
    v362 = v360_account
    v363 = v353_data_len
    v364 = v354_data
    ret
}

// Function 29
func __main__.assert_only_once{syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt}(id : felt){
    v371_callers_function_frame = v365_account
    v372_return_instruction = v366_caller_address
    v373 = v367_syscall_ptr
    v374 = v368_pedersen_ptr
    let (v375_res) = read(v374)
    assert v375_res = 0    // 0x0
    v376 = v372_return_instruction
    v377 = v373
    v378 = v374
    ret
}
