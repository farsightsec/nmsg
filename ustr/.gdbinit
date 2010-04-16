###############################################################################
#  gdb "user functions" to help when developing with Ustr                     #
###############################################################################

define ustr__ret_bits
  set $_bit_allocd = $arg0->data[0] & 0x80
  set $_bit_has_sz = $arg0->data[0] & 0x40
  set $_bit_nexact = $arg0->data[0] & 0x20
  set $_bit_enomem = $arg0->data[0] & 0x10
end

define ustr__ret_refn
  ustr__ret_bits $arg0
  set $__num = $arg0->data[0] & 0x0C

  if  $_bit_has_sz && $__num == 0
    set $_refn = 2
  end
  if !$_bit_has_sz && $__num == 0
    set $_refn = 0
  end

  if  $_bit_has_sz && $__num == 4
    set $_refn = 4
  end
  if !$_bit_has_sz && $__num == 4
    set $_refn = 1
  end

  if  $_bit_has_sz && $__num == 8
    set $_refn = 8
  end
  if !$_bit_has_sz && $__num == 8
    set $_refn = 2
  end

  if  $_bit_has_sz && $__num == 12
    print "** ERROR **"
  end
  if !$_bit_has_sz && $__num == 12
    set $_refn = 4
  end
end

define pustr_refn
  ustr__ret_refn $arg0
  printf "Ref is %u Bytes long\n", $_refn
end

define ustr__ret_lenn
  ustr__ret_bits $arg0
  set $__num = $arg0->data[0] & 0x03

  if  $_bit_has_sz && $__num == 0
    set $_lenn = 2
  end
  if !$_bit_has_sz && $__num == 0
    set $_lenn = 0
  end

  if  $_bit_has_sz && $__num == 1
    set $_lenn = 4
  end
  if !$_bit_has_sz && $__num == 1
    set $_lenn = 1
  end

  if  $_bit_has_sz && $__num == 2
    set $_lenn = 8
  end
  if !$_bit_has_sz && $__num == 2
    set $_lenn = 2
  end

  if  $_bit_has_sz && $__num == 3
    print "** ERROR **"
  end
  if !$_bit_has_sz && $__num == 3
    set $_lenn = 4
  end
end

define pustr_lenn
  ustr__ret_lenn $arg0
  printf "Len is %u Bytes long\n", $_lenn
end

define ustr__ret_num
    set $__ptr  = $arg0->data + 1 + $arg1
    set $__tmpn = $arg2
    set $_num  = 0
    while $__tmpn > 0
      set $__tmpn = $__tmpn - 1

      set $_num = $_num << 8
      set $_num = $_num + $__ptr[$__tmpn]
    end
end

define ustr__ret_ref
  ustr__ret_refn $arg0
  set $_ref = 0
  if $_refn
    ustr__ret_num $arg0 0 $_refn
    set $_ref = $_num
  end
end

define pustr_ref
  ustr__ret_ref $arg0
  if $_refn
    printf "Ref = %u\n", $_ref
  else
    printf "Ref = <none>\n"
  end
end

define ustr__ret_len
  ustr__ret_refn $arg0
  ustr__ret_lenn $arg0
  set $_len = 0
  if $_lenn
    ustr__ret_num $arg0 $_refn $_lenn
    set $_len = $_num
  end
end

define pustr_len
  ustr__ret_len $arg0
  printf "Len = %u\n", $_len
end

define ustr__ret_sz
  ustr__ret_refn $arg0
  ustr__ret_lenn $arg0
  set $_szn = 0
  set $_sz  = 0
  if $_bit_has_sz && $_lenn
    set $_szn = $_lenn
    set $__skip = $_refn + $_lenn
    ustr__ret_num $arg0 $__skip $_szn
    set $_sz  = $_num
  end
end

define pustr_szn
  ustr__ret_sz $arg0
  printf "Sz  is %u Bytes long\n", $_szn
end

define pustr_sz
  ustr__ret_sz $arg0
  if $_szn
    printf "Sz  = %u\n", $_sz
  else
    printf "Sz  = <none>\n"
  end
end

define ustr__ret_oh
  ustr__ret_sz $arg0
  set $_oh = 0
  if $_len
    set $_oh = 1 + $_refn + $_lenn + $_szn + 1
  end
end

define ustr__ret_used
  ustr__ret_len $arg0
  ustr__ret_oh  $arg0
  set $_used = $_len + $_oh
end

define pustr_used
  ustr__ret_used $arg0
  printf "Mem used = %u\n", $_used
end

define pustr_cstr
  ustr__ret_sz $arg0
  if $_lenn
    print (const char *)$arg0->data + 1 + $_refn + $_lenn + $_szn
  else
    print (const char *)""
  end
end

define pustr_info
  if ! $arg0->data[0]
    printf "This Ustr is the empty string: \"\"\n"
    printf "  Is in read-only memory.\n"
  else
    printf "This Ustr has[%x]:\n", $arg0->data[0]

    ustr__ret_refn $arg0
    if $_bit_allocd
      if $_bit_has_sz
        printf "  Does store size metadata.\n"
      else
        printf "  Does not store size metadata.\n"
      end
      if !$_bit_nexact
        printf "  Does exact byte memory allocations.\n"
      end
    else
      if $_bit_has_sz
        printf "  Is in fixed memory.\n"
      else
        printf "  Is in read-only memory.\n"
      end
      if !$_bit_nexact
        printf "  Is limited to an exact byte size (all allocations fail).\n"
      end
    end
    if $_bit_enomem
      printf "  Has had memory allocation errors.\n"
    end

    if $_refn
      printf "  "
      pustr_refn $arg0
    end

    printf "  "
    pustr_lenn $arg0

    printf "  "
    pustr_szn  $arg0

    printf "  "
    pustr_used $arg0
  end
end

define pustr_all
  if ! $arg0
    printf "This Ustr is NULL\n"
  else
    pustr_info $arg0
    pustr_ref  $arg0
    pustr_len  $arg0
    pustr_sz   $arg0
    pustr_cstr $arg0
  end
end

define pustr
  if ! $arg0
    printf "This Ustr is NULL\n"
  else
    pustr_cstr $arg0
    pustr_len  $arg0

    ustr__ret_sz $arg0
    if $_szn
      pustr_sz   $arg0
    end
  end
end
