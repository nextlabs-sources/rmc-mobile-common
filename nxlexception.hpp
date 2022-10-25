#ifndef __NXL_EXCEPTION_HPP__
#define __NXL_EXCEPTION_HPP__

#include <string>
#include <exception>
#include <stdint.h>
namespace nxl {

    class exception : public std::exception {
    public:

        exception() : std::exception(), file_(NULL), func_(NULL), line_(-1), what_(NULL) {
        }

        explicit exception(const char* file,
                const char* func,
                int line,
                const char* what) : std::exception(), file_(file), func_(func), line_(line), what_(what) {
        }

        virtual ~exception() {

        }
    public:

        inline const char* file() const {
            return file_;
        }

        inline const char* func() const {
            return func_;
        }

        inline int line() const {
            return line_;
        }

        virtual const char* what() const throw () {
            return what_;
        }

        std::string details() const {
            std::string s;
            s += what_;
            s += "\n File: ";
            s += file_;
            s += "\n Func: ";
            s += func_;
            s += "\n Line: ";
            {
                char _Buf[2 * 32];
                sprintf(_Buf, "%d", line_);
                s += _Buf;
            }

            return s.c_str();
        }
    protected:
        mutable char const* file_;
        mutable char const* func_;
        mutable int line_;
        mutable char const* what_;

    };
}

#define NXEXCEPTION(what)   nxl::exception(__FILE__, __FUNCTION__, __LINE__,what)

#endif // __NXL_EXCEPTION_HPP__
