#ifndef LanternOS_Header_KERNEL_TERMINAL_H
#define LanternOS_Header_KERNEL_TERMINAL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static char escapeChars[] = {'a', 'b', 'f', 'n', 'r', 't', 'v', '\\', '\'', '\"', '?', ' '};
static char normalChars[] = {'\a', '\b', '\f', '\n', '\r', '\t', '\v', '\\', '\'', '\"', '\?', ' '};

static char parse_escapes(const char *str) {
    if(str == NULL) {
        return '\0';
    }

    if(*str != '\\') {
        return *str;
    }

    const char *paramStr = str + 1;
    if(*paramStr == 'x') {
        char firstBit = *(paramStr + 1), lastBit = *(paramStr + 2); // First bit and second bit in hexadecimal number(8-bit)
        // To capital
        (firstBit >= 'a' && firstBit <= 'z') ? (firstBit = firstBit - 'a' + 'A') : 0;
        (lastBit >= 'a' && lastBit <= 'z') ? (lastBit = lastBit - 'a' + 'A') : 0;

        char result = 0;
        // Deal with first bit
        if(firstBit >= 'A' && firstBit <= 'F') {
            result += (firstBit - 'A' + 10) * 16;
        } else if(firstBit >= '0' && firstBit <= '9') {
            result += (firstBit - '0') * 16;
        } else {
            return '\0';
        }

        // Deal with second bit
        if(lastBit >= 'A' && lastBit <= 'F') {
            result += lastBit - 'A' + 10;
        } else if(lastBit >= '0' && lastBit <= '9') {
            result += lastBit - '0';
        } else {
            return '\0';
        }

        return result;
    }

    for(uint64_t i = 0; i < sizeof(escapeChars); ++i) {
        if(*paramStr == escapeChars[i]) {
            return normalChars[i];
        }
    }

    return *paramStr;
}

// Escaped string to normal(e.g."Hello,\ World!\\n" to "Hello, World!\n")
void escape_to_normal(char *normal_str, const char *escape_str, uint64_t max_buffer_size) {
    for(const char *base = normal_str; *escape_str != '\0' && (uint64_t)(normal_str - base) < max_buffer_size; *normal_str = parse_escapes(escape_str), ((*escape_str == '\\') ? ((*(escape_str + 1) == 'x') ? escape_str += 5 : ++escape_str, ++escape_str) : ++escape_str), ++normal_str);
    *normal_str = '\0';
}

void normal_to_escape(char *escape_str, const char *normal_str, uint64_t max_buffer_size) {
    for(const char *base = escape_str; *normal_str != '\0'; ++normal_str) {
        if((uint64_t)(escape_str - base) >= max_buffer_size) {
            return;
        }
        bool escapeFlag = false;
        for(uint64_t i = 0; i < sizeof(normalChars); ++i) {
            if(normalChars[i] == *normal_str) {
                *(escape_str++) = '\\';
                if((uint64_t)(escape_str - base) >= max_buffer_size) {
                    return;
                }
                *(escape_str++) = escapeChars[i];
                escapeFlag = true;
                break; // Optimization
            }
        }
        if(escapeFlag) {
            continue;
        }
        *(escape_str++) = *normal_str;
    }
}

void parse_commandline(const char *commandline, char *params, uint64_t max_buffer_size) {
    for(char *base = params; *commandline != '\0' && (uint64_t)(params - base) < max_buffer_size; ++commandline) {
        if(*commandline == '\"') {
            ++commandline;
            uint64_t str_size = 0;
            for(; commandline[str_size] != '\"' && commandline[str_size] != '\0' && str_size < max_buffer_size - (params - base); ++str_size);
            if(str_size >= max_buffer_size - (params - base)) {
                return;
            } else if(str_size == 0) {
                continue;
            }
            char temp_base[str_size], *temp = temp_base;
            for(; (uint64_t)(temp - temp_base) < str_size; *(temp++) = *commandline, ++commandline);
            *temp = '\0';
            normal_to_escape(params, temp_base, max_buffer_size - (params - base));
            while(*(++params) != '\0');
            *(params++) = '\n'; // Split the param by '\n'
        } else if(*commandline == '\'') {
            ++commandline;
            uint64_t str_size = 0;
            for(; commandline[str_size] != '\'' && commandline[str_size] != '\0' && str_size < max_buffer_size - (params - base); ++str_size);
            if(str_size >= max_buffer_size - (params - base)) {
                return;
            } else if(str_size == 0) {
                continue;
            }
            char temp_base[str_size], *temp = temp_base;
            for(; (uint64_t)(temp - temp_base) < str_size; *(temp++) = *commandline, ++commandline);
            *temp = '\0';
            normal_to_escape(params, temp_base, max_buffer_size - (params - base));
            while(*(++params) != '\0');
            *(params++) = '\n'; // Split the param by '\n'
        } else if(*commandline == ' ' && *(commandline - 1) != '\\') {
            if(*(params - 1) == ' ' || *(params - 1) == '\n') {
                continue;
            }
            *(params++) = '\n'; // Split the param by '\n'
        } else {
            *(params++) = *commandline;
        }
    }
    *(params++) = '\0';
}

bool parse_param(char *param, const char *params, uint64_t index) {
    for(uint64_t spliternum = 0; spliternum < index && *params != '\0'; (*(params++) == '\n') ? ++spliternum : 0);
    if(*params == '\0') {
        return false;
    }
    uint64_t param_size = 0;
    while(*(params + param_size) != '\n' && *(params + param_size) != '\0') ++param_size;
    char temp[param_size + 1];
    memcpy(temp, params, param_size);
    temp[param_size] = '\0';
    escape_to_normal(param, temp, param_size);
    return true;
}

#endif
