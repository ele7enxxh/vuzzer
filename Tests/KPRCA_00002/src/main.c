/*
 * Author: Brian Pak <brian.pak@kapricasecurity.com>
 * 
 * Copyright (c) 2014 Kaprica Security, Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * 
 */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/mman.h>

#define CODE_SZ 4000
#define STACK_SZ 1000

#define STDOUT 1
#define STDIN 0

#define ERR_OK  0
#define ERR_INV 1
#define ERR_OVF 2
#define ERR_UNF 3

#define OP_UNARY  1
#define OP_BINARY 2

#define BYTE1(x) (x & 0xff)
#define BYTE2(x) ((x >> 8) & 0xff)
#define BYTE3(x) ((x >> 16) & 0xff)
#define BYTE4(x) ((x >> 24) & 0xff)

#define EMIT_BYTE(b) (*(jit->code_ptr++) = b)

#define ASSERT_UNF(opns) \
	if (jit->count < opns) { \
		return ERR_UNF; \
	}

#if PATCHED
#define ASSERT_OVF(sz) \
	if (jit->stack_ptr < jit->stack || \
			jit->code_ptr + (sz) >= jit->code + CODE_SZ) { \
		return ERR_OVF; \
	}
#else
#define ASSERT_OVF(sz)
#endif

/* Changes */
typedef int (*consumer_t) (void *arg, const char *buf, size_t n);

int receive(int fd, void *buf, size_t count, size_t *rx_bytes){
	size_t tmp = read(fd, buf, count);
	if(tmp == -1) // in case of error
		return tmp;
	if(rx_bytes!=NULL) // in case of rx_bytes is not null
		*(rx_bytes) = tmp;
	return 0;
}

int transmit(int fd, const char *buf, size_t count, size_t *rx_bytes){
	size_t tmp = write(fd, buf, count);
	if(tmp == -1) // in case of error
		return tmp;
	if(rx_bytes!=NULL) // in case of rx_bytes is not null
		*(rx_bytes) = tmp; 
	return 0;
}

int allocate(size_t length, int is_X, void **addr){
	*(addr) = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if(*(addr) == NULL)
		return -1;
	return 0;
}

size_t receive_until( char *dst, char delim, size_t max )
{
	size_t len = 0;
	size_t rx = 0;
	char c = 0;

	while( len < max ) {
		dst[len] = 0x00;

		rx = read(0, &c, 1);
		if ( rx == 0 ) {
			len = 0;
			goto end;
		}

		if ( c == delim ) {
			goto end;
		}

		dst[len] = c;
		len++;
	}
end:
	return len;
}

static char *_print_base(char *outend, int *n, unsigned int val, unsigned int base, int uppercase)
{
    *n = 0;
    if (base < 2 || base > 16)
        return outend;

    if (val == 0)
    {
        *n = 1;
        *(--outend) = '0';
        return outend;
    }

    const char *str;
    if (uppercase)
        str = "0123456789ABCDEF";
    else
        str = "0123456789abcdef";

    while (val > 0)
    {
        (*n)++;
        *(--outend) = str[val % base];
        val /= base;
    }

    return outend;
}

static char *_print_signed(char *outbuf, int *n, int val)
{
    int neg = 0;
    if (val < 0)
    {
        neg = 1;
        val = -val;
    }
    char *s = _print_base(outbuf, n, (unsigned int)val, 10, 0);
    if (neg)
    {
        *(--s) = '-';
        (*n)++;
    }
    return s;
}

static int _printf(consumer_t consumer, void *arg, const char *fmt, va_list ap)
{
    char tmpbuf[32]; /* must be at least 32 bytes for _print_base */
    const char *fmtstr = NULL;
    char modifier = 0;
    int n, total = 0;

#define CONSUME(b, c) \
    do { \
        size_t tmp = (size_t)(c); \
        if (tmp == 0) break; \
        total += (n = consumer(arg, (b), tmp)); \
        if (n < 0) goto error; \
        if (n < tmp) goto done; \
    } while (0)

#define FLUSH() \
    do { \
        if (fmtstr) { \
            CONSUME(fmtstr, fmt-fmtstr); \
            fmtstr = NULL; \
        } \
    } while (0)

    while (*fmt)
    {
        int flags = 0;
#define FLAG_ZERO_PADDING 0x01
        unsigned int field_width = 0;

        if (*fmt != '%')
        {
            if (fmtstr == NULL)
                fmtstr = fmt;
            fmt++;
            continue;
        }

        FLUSH();

        fmt++;
        if (*fmt == '%')
        {
            CONSUME(fmt, 1);
            fmt++;
            continue;
        }

        /* process flags */
        while (1)
        {
            switch (*fmt)
            {
            case '0':
                flags |= FLAG_ZERO_PADDING;
                fmt++;
                break;
            default:
                goto flags_done;
            }
        }

flags_done:
        /* process field width */
        field_width = strtoul(fmt, (char **)&fmt, 10);

        /* process modifiers */
        switch (*fmt)
        {
        case 'H':
        case 'h':
        case 'l':
            modifier = *fmt;
            fmt++;
            break;
        }

        /* process conversion */
        char *tmpstr;
        int base, outlen, sv;
        unsigned int uv;
        void *pv;
        switch(*fmt)
        {
        case 'd':
        case 'i':
            sv = va_arg(ap, int);
            if (modifier == 'h') sv = (short)(sv & 0xffff);
            else if (modifier == 'H') sv = (signed char)(sv & 0xff);
            tmpstr = _print_signed(tmpbuf + 32, &outlen, sv);
            while (field_width > outlen)
            {
                CONSUME((flags & FLAG_ZERO_PADDING) ? "0" : " ", 1);
                field_width--;
            }
            CONSUME(tmpstr, outlen);
            fmt++;
            break;
        case 'u':
        case 'o':
        case 'x':
        case 'X':
            if (*fmt == 'u') base = 10;
            else if(*fmt == 'o') base = 8;
            else base = 16;
            uv = va_arg(ap, unsigned int);
            if (modifier == 'h') uv &= 0xffff;
            else if (modifier == 'H') uv &= 0xff;
            tmpstr = _print_base(tmpbuf + 32, &outlen, uv, base, *fmt == 'X');
            while (field_width > outlen)
            {
                CONSUME((flags & FLAG_ZERO_PADDING) ? "0" : " ", 1);
                field_width--;
            }
            CONSUME(tmpstr, outlen);
            fmt++;
            break;
        case 'n':
            pv = va_arg(ap, void *);
            if (modifier == 'h') *(short int *)pv = total;
            else if (modifier == 'H') *(signed char *)pv = total;
            else *(int *)pv = total;
            fmt++;
            break;
        case 's':
            pv = va_arg(ap, void *);
            CONSUME((char *)pv, strlen((char *)pv));
            fmt++;
            break;
        }
    }
    FLUSH();

done:
    return total;
error:
    return -1;
}

static int _consumer_fd(void *arg, const char *buf, size_t n)
{
    size_t tx;
    transmit((int)arg, buf, n, &tx);
    return (int)n;
}


int fdprintf(int fd, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int ret = _printf(_consumer_fd, (void *)fd, fmt, ap);
    va_end(ap);
    return ret;
}

/* Changes Ends */
typedef struct jit {
	char code[CODE_SZ];
	int stack[STACK_SZ/sizeof(int)];
	char *code_ptr;
	int *stack_ptr;
	int count;
} jit_t;
#define JITStackEnd (jit->stack + STACK_SZ/sizeof(int))

#define MAX_OUTPUT (64*1024)
static char *g_output_buf = NULL;
static size_t g_output_len = 0;

int readuntil(int fd, char *buf, size_t len, char delim)
{
	size_t i;
	char *c = buf;
	for (i = 0; i < len; ++i)
	{
		size_t rx;
		if (receive(fd, c, 1, &rx) != 0 || rx == 0){
			printf("%zd\n",rx);
			break;
		}
		if (*(c++) == delim)
			break;
	}
	*(c-1) = '\0';
	//printf("%s\n",buf);
	return c - buf;
}

int jit_int(jit_t *jit, int n)
{
	/* Push the old value and pull in a new value.
	 *
	 * mov  $stack_ptr, %ecx
	 * mov  %edi, [%ecx]
	 * xchg %edi, %eax
	 * mov  $n, %eax
	 */
	int sp = (int) (jit->stack_ptr - 1);
	char code[] = { 0xb9, BYTE1(sp), BYTE2(sp), BYTE3(sp), BYTE4(sp), 0x89,
		0x39, 0x97, 0xb8, BYTE1(n), BYTE2(n), BYTE3(n), BYTE4(n) };

	ASSERT_OVF(sizeof(code));
	memcpy(jit->code_ptr, code, sizeof(code));
	jit->code_ptr += sizeof(code);
	jit->stack_ptr--;
	jit->count++;

	return ERR_OK;
}

int jit_op(jit_t *jit, char op)
{
	int sp = (int) (jit->stack_ptr);

	switch (op)
	{
		case '+':           /* add */
			ASSERT_OVF(9);
			ASSERT_UNF(OP_BINARY);
			EMIT_BYTE(0x01); EMIT_BYTE(0xf8);
			EMIT_BYTE(0xb9);
			EMIT_BYTE(BYTE1(sp)); EMIT_BYTE(BYTE2(sp)); EMIT_BYTE(BYTE3(sp)); EMIT_BYTE(BYTE4(sp));
			EMIT_BYTE(0x8b); EMIT_BYTE(0x39);
			jit->stack_ptr += 1;
			jit->count -= 1;
			break;

		case '-':           /* sub */
			ASSERT_OVF(9);
			ASSERT_UNF(OP_BINARY);
			EMIT_BYTE(0x29); EMIT_BYTE(0xf8);
			EMIT_BYTE(0xb9);
			EMIT_BYTE(BYTE1(sp)); EMIT_BYTE(BYTE2(sp)); EMIT_BYTE(BYTE3(sp)); EMIT_BYTE(BYTE4(sp));
			EMIT_BYTE(0x8b); EMIT_BYTE(0x39);
			jit->stack_ptr += 1;
			jit->count -= 1;
			break;

		case '*':           /* mul */
			ASSERT_OVF(10);
			ASSERT_UNF(OP_BINARY);
			EMIT_BYTE(0x0f); EMIT_BYTE(0xaf); EMIT_BYTE(0xc7);
			EMIT_BYTE(0xb9);
			EMIT_BYTE(BYTE1(sp)); EMIT_BYTE(BYTE2(sp)); EMIT_BYTE(BYTE3(sp)); EMIT_BYTE(BYTE4(sp));
			EMIT_BYTE(0x8b); EMIT_BYTE(0x39);
			jit->stack_ptr += 1;
			jit->count -= 1;
			break;

		case '/':           /* div */
			ASSERT_OVF(22);
			ASSERT_UNF(OP_BINARY);
			EMIT_BYTE(0x83); EMIT_BYTE(0xff); EMIT_BYTE(0x00);
			EMIT_BYTE(0x75); EMIT_BYTE(0x07); EMIT_BYTE(0x31);
			EMIT_BYTE(0xc0); EMIT_BYTE(0x40); EMIT_BYTE(0x89);
			EMIT_BYTE(0xc3); EMIT_BYTE(0xcd); EMIT_BYTE(0x80);
			EMIT_BYTE(0x99); EMIT_BYTE(0xf7); EMIT_BYTE(0xff);
			EMIT_BYTE(0xb9);
			EMIT_BYTE(BYTE1(sp)); EMIT_BYTE(BYTE2(sp)); EMIT_BYTE(BYTE3(sp)); EMIT_BYTE(BYTE4(sp));
			EMIT_BYTE(0x8b); EMIT_BYTE(0x39);
			jit->stack_ptr += 1;
			jit->count -= 1;
			break;

		case '^':           /* pow */
			ASSERT_OVF(29);
			ASSERT_UNF(OP_BINARY);
			EMIT_BYTE(0x57); EMIT_BYTE(0x31); EMIT_BYTE(0xc9);
			EMIT_BYTE(0x41); EMIT_BYTE(0x83); EMIT_BYTE(0xff);
			EMIT_BYTE(0x00); EMIT_BYTE(0x7c); EMIT_BYTE(0x0a);
			EMIT_BYTE(0x85); EMIT_BYTE(0xff); EMIT_BYTE(0x74);
			EMIT_BYTE(0x07); EMIT_BYTE(0x0f); EMIT_BYTE(0xaf);
			EMIT_BYTE(0xc8); EMIT_BYTE(0x4f); EMIT_BYTE(0xeb);
			EMIT_BYTE(0xf6); EMIT_BYTE(0x49); EMIT_BYTE(0x5f);
			EMIT_BYTE(0x91);
			EMIT_BYTE(0xb9);
			EMIT_BYTE(BYTE1(sp)); EMIT_BYTE(BYTE2(sp)); EMIT_BYTE(BYTE3(sp)); EMIT_BYTE(BYTE4(sp));
			EMIT_BYTE(0x8b); EMIT_BYTE(0x39);
			jit->stack_ptr += 1;
			jit->count -= 1;
			break;

		case '|':           /* abs */
			ASSERT_OVF(14);
			ASSERT_UNF(OP_UNARY);
			EMIT_BYTE(0x52); EMIT_BYTE(0x89); EMIT_BYTE(0xc1);
			EMIT_BYTE(0xc1); EMIT_BYTE(0xf9); EMIT_BYTE(0x1f);
			EMIT_BYTE(0x89); EMIT_BYTE(0xca); EMIT_BYTE(0x31);
			EMIT_BYTE(0xc2); EMIT_BYTE(0x29); EMIT_BYTE(0xca);
			EMIT_BYTE(0x92); EMIT_BYTE(0x5a);
			break;

		case '~':           /* neg */
			ASSERT_OVF(2);
			ASSERT_UNF(OP_UNARY);
			EMIT_BYTE(0xf7); EMIT_BYTE(0xd8);
			break;

		case '!':           /* not */
			ASSERT_OVF(2);
			ASSERT_UNF(OP_UNARY);
			EMIT_BYTE(0xf7); EMIT_BYTE(0xd0);
			break;

		default:            /* nop */
			EMIT_BYTE(0x90); break;
	}

	return 0;
}

int main()
{
	char buf[8192];
	g_output_buf = malloc(MAX_OUTPUT);
	if (g_output_buf == NULL)
	{
		fdprintf(STDOUT, "Failed to allocate output buffer.\n");
		return -1;
	}

	/* Allocate JIT struct */
	jit_t *jit;
	if (allocate(sizeof(jit_t), 1, (void **)&jit) != 0)
	{
		fdprintf(STDOUT, "Failed to allocate JIT struct.\n");
		return -1;
	}

	fdprintf(STDOUT, "> ");
	/* Main RPN loop */
	while(readuntil(STDIN, buf, sizeof(buf), '\n') > 0)
	{
		int val = 0;
		int error = ERR_OK;
		printf("%s\n",buf);
		if (strcmp(buf, "quit") == 0)
		{
			fdprintf(STDOUT, "QUIT\n");
			return 0;
		}

		if (strlen(buf) > 0)
		{
			jit->code_ptr = jit->code;
			jit->stack_ptr = JITStackEnd;
			jit->count = 0;

			char prologue[] = { 0x55, 0x8b, 0xec, 0x81, 0xec, 0xff, 0x00, 0x00, 0x00, 0x51, 0x31, 0xc0, 0x89, 0xc2 };
			memcpy(jit->code_ptr, prologue, sizeof(prologue));
			jit->code_ptr += sizeof(prologue);

			char *tok, *input = buf;
			while (*input && input < buf + strlen(buf))
			{
				if (isspace(*input))
				{
					input++;
					continue;
				}

				int n = strtol(input, &tok, 0);
				if (input == tok)
				{
					/* Operator */
					char c = *(input + 1);
					if (!isspace(c) && c != '\0')
					{
						error = ERR_INV;
						break;
					}
					error = jit_op(jit, *input);
					input++;
				}
				else
				{
					/* Number */
					error = jit_int(jit, n);
					input = tok;
				}
			}

			char epilogue[] = { 0x59, 0x8b, 0xe5, 0x5d, 0xc3 };
			if (jit->code_ptr + sizeof(epilogue) >= jit->code + CODE_SZ) {
				error = ERR_OVF;
			}
			else
			{
				memcpy(jit->code_ptr, epilogue, sizeof(epilogue));
				jit->code_ptr += sizeof(epilogue);

				/* Execute JIT'd code */
				val = ((int (*)(void)) jit->code)();
			}
		}

		if (error != ERR_OK)
			fdprintf(STDOUT, "Error!\n");
		else
			fdprintf(STDOUT, "%d (0x%08x)\n", val, val);
		fdprintf(STDOUT, "> ");
	}

	return 0;
}
