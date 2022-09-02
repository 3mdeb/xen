/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/compiler.h>
#include <xen/string.h>

/**
 * memcpy - Copy one area of memory to another
 * @dest: Where to copy to
 * @src: Where to copy from
 * @count: The size of the area.
 *
 * You should not use this function to access IO space, use memcpy_toio()
 * or memcpy_fromio() instead.
 */
void *(memcpy)(void *dest, const void *src, size_t count)
{
	char *tmp = (char *) dest, *s = (char *) src;

	while (count--)
		*tmp++ = *s++;

	return dest;
}

#define movs(type,to,from) \
	asm volatile("movs" type:"=&D" (to), "=&S" (from):"0" (to), "1" (from):"memory")

static always_inline void rep_movs(void *to, const void *from, size_t n)
{
	unsigned long d0, d1, d2;
	asm volatile("rep ; movsl\n\t"
		     "testb $2,%b4\n\t"
		     "je 1f\n\t"
		     "movsw\n"
		     "1:\ttestb $1,%b4\n\t"
		     "je 2f\n\t"
		     "movsb\n"
		     "2:"
		     : "=&c" (d0), "=&D" (d1), "=&S" (d2)
		     : "0" (n / 4), "q" (n), "1" ((long)to), "2" ((long)from)
		     : "memory");
}

void memcpy_fromio(void *to, const volatile void *from, size_t n)
{
	if (unlikely(!n))
		return;

	/* Align any unaligned source IO */
	if (unlikely(1 & (unsigned long)from)) {
		movs("b", to, from);
		n--;
	}
	if (n > 1 && unlikely(2 & (unsigned long)from)) {
		movs("w", to, from);
		n-=2;
	}
	rep_movs(to, (const void *)from, n);
}

void memcpy_toio(volatile void *to, const void *from, size_t n)
{
	if (unlikely(!n))
		return;

	/* Align any unaligned destination IO */
	if (unlikely(1 & (unsigned long)to)) {
		movs("b", to, from);
		n--;
	}
	if (n > 1 && unlikely(2 & (unsigned long)to)) {
		movs("w", to, from);
		n-=2;
	}
	rep_movs((void *)to, (const void *) from, n);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
