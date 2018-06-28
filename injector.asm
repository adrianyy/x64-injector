public main

extern MessageBoxA				: proc
extern OpenProcess				: proc
extern VirtualAllocEx			: proc
extern CreateRemoteThread		: proc
extern CloseHandle				: proc
extern WriteProcessMemory		: proc
extern GetModuleHandleA			: proc
extern GetProcAddress			: proc
extern CreateToolhelp32Snapshot	: proc
extern Process32First			: proc
extern Process32Next			: proc
extern strcmp					: proc

.data
msg_title		db  "x64 dll injector",	0
msg_not_found	db  "Process is not running.", 0
msg_cant_inject db  "Injection failed.", 0
msg_success		db  "Injection succeded.", 0

kernel32		db  "kernel32.dll", 0
load_library	db  "LoadLibraryA", 0
target_process	db  "notepad.exe", 0
library_name	db  "D:\\D.dll", 0
library_len		equ $ - library_name

.code
find_process proc

	push	r12								; r12 = toolhelp32 snapshot handle
	push	r13								; r13 = found pid
	push	rbp
	mov		rbp, rsp

	sub		rsp,  150h
	and		rsp, -10h
	xor		r13, r13

	mov		qword ptr [rsp + 20h], 130h		; dwSize
	mov		rcx, 2							; TH32CS_SNAPPROCESS
	xor		rdx, rdx
	call	CreateToolhelp32Snapshot

	mov		r12, rax
	cmp		r12, -1
	je		exit
	
	mov		rcx, r12
	lea		rdx, [rsp + 20h]
	call	Process32First

	cmp		rax, 0
	je		exit_cleanup

	process_loop:
		lea		rcx, target_process
		lea		rdx, [rsp + 20h + 2Ch]
		call	strcmp

		cmp		rax, 0
		je		found

		mov		rcx, r12
		lea		rdx, [rsp + 20h]
		call	Process32Next

		cmp		rax, 0
		jne		process_loop

	exit_cleanup:
		mov		rcx, r12
		call	CloseHandle

	exit:
		mov		eax, r13d
		mov		rsp, rbp
		pop		rbp
		pop		r13
		pop		r12
		ret

	found:
		mov		r13d, dword ptr [rsp + 20h + 8h]
		jmp		exit_cleanup

find_process endp

get_load_library proc
	
	push	rbp
	mov		rbp, rsp

	sub		rsp,  20h
	and		rsp, -10h

	lea		rcx, kernel32
	call	GetModuleHandleA

	mov		rcx, rax
	lea		rdx, load_library
	call	GetProcAddress

	mov		rsp, rbp
	pop		rbp
	ret

get_load_library endp

inject_image proc

	push	r12							; r12 = process handle
	push	r13							; r13 = allocated memory
	push	r14							; r14 = injection status
	push	rbp
	mov		rbp, rsp

	sub		rsp,  38h
	and		rsp, -10h
	xor		r14, r14
	
	mov		r12, rcx
	mov		rcx, 1FFFFFh				; PROCESS_ALL_ACCESS
	xor		rdx, rdx
	mov		r8 , r12
	call	OpenProcess

	mov		r12, rax
	cmp		r12, -1
	je		exit

	mov		rcx, r12
	xor		rdx, rdx
	mov		r8 , library_len
	mov		r9 , 3000h					; MEM_COMMIT | MEM_RESERVE
	mov     qword ptr [rsp + 20h], 4	; PAGE_READWRITE
	call	VirtualAllocEx

	mov		r13, rax
	cmp		r13, 0
	je		exit_cleanup

	mov		rcx, r12
	mov		rdx, r13
	lea		r8 , library_name
	mov		r9 , library_len
	mov     qword ptr [rsp + 20h], 0
	call	WriteProcessMemory

	cmp		rax, 0
	je		exit_cleanup

	call	get_load_library
	
	cmp		rax, 0
	je		exit_cleanup

	mov		rcx, r12
	xor		rdx, rdx
	xor		r8 , r8
	mov		r9 , rax
	mov     qword ptr [rsp + 20h], r13
	mov     qword ptr [rsp + 28h], 0
	mov     qword ptr [rsp + 30h], 0
	call	CreateRemoteThread

	mov		rcx, rax
	call	CloseHandle
	mov		r14, 1

	exit_cleanup:
		mov		rcx, r12
		call	CloseHandle

	exit:
		mov		rax, r14
		mov		rsp, rbp
		pop		rbp
		pop		r14
		pop		r13
		pop		r12
		ret

inject_image endp

main proc
	
	push	rbp
	mov		rbp, rsp

	sub		rsp,  20h
	and		rsp, -10h

	call	find_process
	cmp		rax, 0
	je		process_not_found

	mov		rcx, rax
	call	inject_image
	cmp		rax, 0
	je		injection_fail

	xor		rcx, rcx
	lea		rdx, msg_success
	lea		r8 , msg_title
	mov		r9 , 40h
	call	MessageBoxA
	jmp		exit

	process_not_found:
		xor		rcx, rcx
		lea		rdx, msg_not_found
		lea		r8 , msg_title
		mov		r9 , 30h
		call	MessageBoxA
		jmp		exit

	injection_fail:
		xor		rcx, rcx
		lea		rdx, msg_cant_inject
		lea		r8 , msg_title
		mov		r9 , 30h
		call	MessageBoxA

	exit:
		mov		rsp, rbp
		pop		rbp
		ret

main endp

end