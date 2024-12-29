#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Depending on the toolchain and its configuration the header can end up quite
 * far from the start of the file.
 */
#define PREFIX_SIZE (8*1024)

struct mle_header
{
    uint8_t uuid[16];
    uint32_t header_len;
    uint32_t version;
    uint32_t entry_point;
    uint32_t first_valid_page;
    uint32_t mle_start;
    uint32_t mle_end;
    uint32_t capabilities;
    uint32_t cmdline_start;
    uint32_t cmdline_end;
} __attribute__ ((packed));

static const uint8_t MLE_HEADER_UUID[] = {
    0x5a, 0xac, 0x82, 0x90, 0x6f, 0x47, 0xa7, 0x74,
    0x0f, 0x5c, 0x55, 0xa2, 0xcb, 0x51, 0xb6, 0x42
};

int main(int argc, char *argv[])
{
    FILE *fp;
    struct mle_header header;
    int i;
    char *end_ptr;
    long long correction;
    const char *file_path;

    if ( argc != 3 )
    {
        fprintf(stderr, "Usage: %s <xen.efi> <entry-correction>\n", argv[0]);
        return 1;
    }

    correction = strtoll(argv[2], &end_ptr, 0);
    if ( *end_ptr != '\0' )
    {
        fprintf(stderr, "Failed to parse '%s' as a number\n", argv[2]);
        return 1;
    }
    if ( correction < INT32_MIN  )
    {
        fprintf(stderr, "Correction '%s' is too small\n", argv[2]);
        return 1;
    }
    if ( correction > INT32_MAX  )
    {
        fprintf(stderr, "Correction '%s' is too large\n", argv[2]);
        return 1;
    }

    file_path = argv[1];

    fp = fopen(file_path, "r+");
    if ( fp == NULL )
    {
        fprintf(stderr, "Failed to open %s\n", file_path);
        return 1;
    }

    for ( i = 0; i < PREFIX_SIZE; i += 16 )
    {
        uint8_t bytes[16];

        if ( fread(bytes, sizeof(bytes), 1, fp) != 1 )
        {
            fprintf(stderr, "Failed to find MLE header in %s\n", file_path);
            goto fail;
        }

        if ( memcmp(bytes, MLE_HEADER_UUID, 16) == 0 )
        {
            break;
        }
    }

    if ( i >= PREFIX_SIZE )
    {
        fprintf(stderr, "Failed to find MLE header in %s\n", file_path);
        goto fail;
    }

    if ( fseek(fp, -16, SEEK_CUR) )
    {
        fprintf(stderr, "Failed to seek back to MLE header in %s\n", file_path);
        goto fail;
    }

    if ( fread(&header, sizeof(header), 1, fp) != 1 )
    {
        fprintf(stderr, "Failed to read MLE header from %s\n", file_path);
        goto fail;
    }

    if ( fseek(fp, -(int)sizeof(header), SEEK_CUR) )
    {
        fprintf(stderr, "Failed to seek back again to MLE header in %s\n",
                file_path);
        goto fail;
    }

    header.entry_point += correction;

    if ( fwrite(&header, sizeof(header), 1, fp) != 1 )
    {
        fprintf(stderr, "Failed to write MLE header in %s\n", file_path);
        goto fail;
    }

    fclose(fp);
    return 0;

fail:
    fclose(fp);
    return 1;
}
