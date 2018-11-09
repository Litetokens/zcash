#ifndef _TRON_LOG_FILE_H__
#define _TRON_LOG_FILE_H__
#include <iostream>


static FILE* file = NULL;
static bool bPrintToConsole = true;
void OpenDebugLog()
{
    std::string pathDebug = "debug.log";
    file = fopen(pathDebug.c_str(), "a");
    if (file)
        setbuf(file, NULL); // unbuffered
}

void CloseDebugLog()
{
    fclose(file);
}

static std::string FORMAT_STRING(const std::string& prefix, const char* format, ...)
{
    const static size_t MAX_FMT = 1024;
    char buf[MAX_FMT];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, MAX_FMT, format, args);
    va_end(args);

    return prefix + std::string(buf);
}

static int LogPrintString(const std::string& str)
{
    int ret = 0; // Returns total number of characters written
    if (bPrintToConsole) {
        ret = fwrite(str.data(), 1, str.size(), stdout);
        fflush(stdout);
    } else {
        ret = fwrite(str.data(), 1, str.size(), file);
    }
    return ret;
}

inline bool LogDebug(const char* format, ...)
{
    std::string stsr = FORMAT_STRING(std::string("INFO: "), format);
    stsr += "\n";
    LogPrintString(stsr);
    return false;
}

inline bool LogError(const char* format, ...)
{
    std::string stsr = FORMAT_STRING(std::string("ERROR: "), format);
    stsr += "\n";
    LogPrintString(stsr);
    return false;
}

inline bool LogWarn(const char* format, ...)
{
    std::string stsr = FORMAT_STRING(std::string("WARN: "), format);
    stsr += "\n";
    LogPrintString(stsr);
    return false;
}


#endif //_TRON_LOG_FILE_H__