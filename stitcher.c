/*
 * Stitcher - an open-source img3 stitching thingy.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"

#define DPRINT printf

void usage() {
	printf("usage: %s -i [img3] -b [raw_blob (not xml, but raw certificate!)]\n", "stitcher");
}

int main(int argc, char *argv[])
{
	char *blobfile = NULL, *img3file = NULL;
	int c;

	while ((c = getopt(argc, argv, "b:i:")) != -1) {
		switch (c) {
		case 'b':
			blobfile = optarg;
			break;
		case 'i':
			img3file = optarg;
			break;
		default:
			usage();
			return -1;
		}
	}

	FILE *img3c, *blobc;

	/* open img3 container */
	img3c = fopen(img3file, "rb+");
	if (!img3c) {
		DPRINT("Failed to open image3 container.\n");
		usage();
		return -1;
	}

	/* open blob container */
	blobc = fopen(blobfile, "rb+");
	if (!blobc) {
		DPRINT("Failed to open blob raw container.\n");
		usage();
		return -1;
	}

	int len;
	fseek(img3c, 0, SEEK_END);
	len = ftell(img3c);
	fseek(img3c, 0, SEEK_SET);
	DPRINT("image3 length is %d\n", len);

	uint8_t *img3_buffer;

	/* allocate memory */
	img3_buffer = malloc(len);
	if (!img3_buffer) {
		DPRINT("Memory allocation failed.\n");
		return;
	}
	memset(img3_buffer, 0, len);
	fread(img3_buffer, len, 1, img3c);
	DPRINT("image3 buffer is at %p\n", img3_buffer);

	int i;
	for (i = 0; i < len; i++) {
		uint8_t *candidate = &img3_buffer[i];
		uint8_t string[] = { 0x48, 0x53, 0x48, 0x53 };
		if (!memcmp(candidate, string, sizeof(uint32_t))) {
			int offset, img3data_length;
			DPRINT("SHSH tag at 0x%08x\n", i);

			offset = i;
			img3data_length = len - offset;
			DPRINT("Total old signature size: %d bytes\n",
			       img3data_length);

			int cert_len;
			fseek(blobc, 0, SEEK_END);
			cert_len = ftell(blobc);
			fseek(blobc, 0, SEEK_SET);
			DPRINT("Blob length: %d bytes\n", cert_len);

			DPRINT("Reading certificate blob\n");
			uint8_t *cert_buffer = malloc(cert_len);
			if (!cert_buffer) {
				DPRINT("Memory allocation failed.\n");
				return;
			}
			memset(cert_buffer, 0, cert_len);
			fread(cert_buffer, cert_len, 1, blobc);

			int total_length = cert_len + offset;
			DPRINT("Total image size: %d bytes\n", total_length);

			DPRINT("Creating full image\n");
			uint8_t *final_img3_buffer = malloc(total_length);
			if (!final_img3_buffer) {
				DPRINT("Memory allocation failed.\n");
				return;
			}
			memset(final_img3_buffer, 0, total_length);

			DPRINT("Copying to target buffer\n");
			memcpy(final_img3_buffer, img3_buffer, i);
			memcpy(final_img3_buffer + i, cert_buffer, cert_len);

			DPRINT("Fixing up image3 header (TODO)\n");
			uint32_t filesize, subfilesize, offsetsize;
			filesize = total_length;
			DPRINT("img3c[overall_file_size]: %x\n", total_length);

			subfilesize = filesize - 0x14;
			DPRINT("img3c[sub_filesize]: %x\n", subfilesize);

			memcpy(&offsetsize, final_img3_buffer + 0xC, sizeof(uint32_t));

#ifdef ENDIAN_BIG
			offsetsize = __builtin_bswap32(offsetsize);
#endif
			offsetsize += 0x40;
			DPRINT("img3c[offset_size]: %x\n", offsetsize);
#ifdef ENDIAN_BIG
			filesize = __builtin_bswap32(filesize);
			subfilesize = __builtin_bswap32(subfilesize);
			offsetsize = __builtin_bswap32(offsetsize);
#endif
			memcpy(final_img3_buffer + 0x4, &filesize, sizeof(uint32_t));
			memcpy(final_img3_buffer + 0x8, &subfilesize, sizeof(uint32_t));
			memcpy(final_img3_buffer + 0xC, &offsetsize, sizeof(uint32_t));

			fclose(img3c);
			fclose(blobc);
			fopen(img3file, "wb+");
			fwrite(final_img3_buffer, total_length, 1, img3c);
			DPRINT("Written signed image.\n");
			fclose(img3c);
		}
	}
	return 0;
}
