# This example has adr instructions referencing code
# ADR won't include the least signficant bit that determines the decode mode
# So thumb_to_thumb and arm_to_thumb transitions need to add 1 to the relative address

.syntax unified
.section .text

.align 2
.arm
.global _start
_start:
    adr r2, .arm_to_arm
    mov pc, r2
    bl exit

.arm_to_arm:
    ldr r0, =ok1_str
    bl puts
    adr r2, .arm_to_thumb
    # adr won't capture the bit in the label so we need to add 1 to change mode
    add r2, r2, #1
    bx r2


.thumb
.arm_to_thumb:
    ldr r0, =ok2_str
    bl puts
    adr r2, .ThumbToThumb
    # adr won't capture the bit in the pc to stay in thumb mode.
    add r2, r2, #1
    bx r2

.ThumbToThumb:
    ldr r0, =ok3_str
    bl puts
    adr r2, .ThumbToArm
    bx r2
.arm
.ThumbToArm:
    ldr r0, =ok4_str
    bl puts
    bl exit

.global	main
.type	main, %function
.thumb
.align 2
main:
    push { lr }
    mov r0, #0
    pop { pc }

.section .rodata
ok1_str:
    .ascii "OK1\n\0"
ok2_str:
    .ascii "OK2\n\0"
ok3_str:
    .ascii "OK3\n\0"
ok4_str:
    .ascii "OK4\n\0"
