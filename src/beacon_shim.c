#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef NOMADX_EXE
#include <windows.h>
extern int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous,
                           LPWSTR command_line, int show);
int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous,
                   LPSTR command_line, int show) {
    (void)command_line;
    return wWinMain(instance, previous, GetCommandLineW(), show);
}
#endif

/* Keep this layout in sync with BeaconFormat in src/coff.zig. */
typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} beacon_formatp;

extern void nx_beacon_append(const char *data, int len);

void BeaconPrintf(int type, char *fmt, ...) {
    (void)type;
    if (!fmt) return;

    va_list ap;
    va_start(ap, fmt);
    int needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (needed <= 0) return;

    char *buffer = (char *)malloc((size_t)needed + 1);
    if (!buffer) return;

    va_start(ap, fmt);
    int written = vsnprintf(buffer, (size_t)needed + 1, fmt, ap);
    va_end(ap);

    if (written > 0) nx_beacon_append(buffer, written);
    free(buffer);
}

void BeaconFormatPrintf(beacon_formatp *format, char *fmt, ...) {
    if (!format || !fmt || !format->buffer) return;

    int remaining = format->size - format->length;
    if (remaining <= 1) return;

    va_list ap;
    va_start(ap, fmt);
    int written = vsnprintf(format->buffer, (size_t)remaining, fmt, ap);
    va_end(ap);

    if (written <= 0) return;
    if (written >= remaining) written = remaining - 1;
    format->length += written;
    format->buffer += written;
}
