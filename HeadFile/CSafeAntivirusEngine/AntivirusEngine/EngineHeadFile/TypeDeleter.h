/*
 * EngineHeadFile/TypeDeleter.h
 * CSafe杀毒引擎中自定义RAII部分
 * Made By Ternary_Operator
 * Copyright (c) 2022 Ternary_Operator
*/

#ifndef TOProtect_Header_TYPEDELETOR_H
#define TOProtect_Header_TYPEDELETOR_H

#include <memory>

struct deleter_HANDLE {
    void operator()(HANDLE hHandle) const {
        CloseHandle(hHandle);
    }
};
struct deleter_HKEY {
    void operator()(HKEY hKey) const {
        RegCloseKey(hKey);
    }
};
template<typename freetype>
struct deleter_free {
	void operator()(freetype ptr) {
		free(ptr);
	}
};

template<typename ProtectedType, typename destructor_struct>
class toSrcProtect {
    public:
    	toSrcProtect() = default;
        toSrcProtect(ProtectedType value) {
            this->_value = value;
            
        }

        ~toSrcProtect() {
            destructor(_value);
        }

        ProtectedType &value() {
            return _value;
        }
        
        ProtectedType &operator()() {
        	return _value;
		}

    private:
    	destructor_struct destructor;
        ProtectedType _value;
};

using safeHANDLE = toSrcProtect<HANDLE, deleter_HANDLE>;
using safeHKEY = toSrcProtect<HKEY, deleter_HKEY>;

#endif