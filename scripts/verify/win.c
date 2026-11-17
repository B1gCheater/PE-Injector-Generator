#include <windows.h>

/* 最小 GUI 子系统程序：调一个 user32 API 确认 libpath 可用，不弹任何窗口 */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int nShow)
{
    (void)hInst; (void)hPrev; (void)cmd; (void)nShow;
    return IsWindow(NULL) ? 1 : 0;
}
