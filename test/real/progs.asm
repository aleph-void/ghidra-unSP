; Test programs for the u'nSP Ghidra module (Apache-2.0, written for Ghidra-Rare).
; Assembled with naken_asm (independent assembler).  Words are addressed from 0x1000.
.unsp
.org 0x1000

main:
  push bp,[sp]
  add bp,sp,#1
  ld r1,#data
  ld r2,#dest
  ld r3,#8
  call memcpy
  ld r1,#dest
  ld r2,#8
  call checksum
  ld r1,#dest
  ld r2,#8
  call sort
  ld r1,#dest
  ld r2,#8
  call strlen
  ld r1,#3
  call dispatch
  call dot4
  pop bp,[sp]
  retf

; void memcpy(r1 = src, r2 = dst, r3 = n)
memcpy:
  push bp,[sp]
  add bp,sp,#1
  cmp r3,#0
  je memcpy_done
memcpy_loop:
  ld r4,[r1++]
  st r4,[r2++]
  sub r3,#1
  jne memcpy_loop
memcpy_done:
  pop bp,[sp]
  retf

; unsigned checksum(r1 = ptr, r2 = n): 16 bit sum, carries folded back
checksum:
  push bp,[sp]
  add bp,sp,#1
  ld r3,#0
checksum_loop:
  add r3,[r1++]
  adc r3,#0
  sub r2,#1
  jne checksum_loop
  ld r1,r3
  pop bp,[sp]
  retf

; r1 = maximum (unsigned) of the array at r1 with r2 elements
sort:
  push r2-r3,[sp]
  push bp,[sp]
  add bp,sp,#1
  ld r3,#0
sort_loop:
  ld r4,[r1++]
  cmp r4,r3
  jbe sort_keep
  ld r3,r4
sort_keep:
  sub r2,#1
  jne sort_loop
  ld r1,r3
  pop bp,[sp]
  pop r2-r3,[sp]
  retf

; r1 = length of the zero terminated word string at r1 (bounded by r2)
strlen:
  ld r3,#0
strlen_loop:
  cmp r3,r2
  jae strlen_end
  ld r4,[r1++]
  cmp r4,#0
  je strlen_end
  add r3,#1
  jmp strlen_loop
strlen_end:
  ld r1,r3
  retf

; computed jump through a table: r1 selects an entry
dispatch:
  cmp r1,#3
  ja dispatch_default
  add r1,#table
  ld pc,[r1]
dispatch_default:
  ld r1,#0xffff
  retf
case0:
  ld r1,#10
  retf
case1:
  ld r1,#11
  retf
case2:
  ld r1,#12
  retf
case3:
  ld r1,#13
  retf
table:
  .dw case0
  .dw case1
  .dw case2
  .dw case3

; MR = 4 term dot product of two vectors, then signed 32 bit result in r4:r3
dot4:
  ld r1,#vec_a
  ld r2,#vec_b
  mac.ss [r1],[r2],4
  mul.us r3,r4
  mul.ss r3,r4
  retf

data:
  .dw 5,4,3,2,1,0,0xffff,7
dest:
  .dw 0,0,0,0,0,0,0,0
vec_a:
  .dw 1,2,3,4
vec_b:
  .dw 5,6,7,8
