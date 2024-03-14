#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <malloc.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <glob.h>
#include "digest.h"
#include "utils.h"

static const size_t sums_len = SHA_DIGEST_LENGTH + MD5_DIGEST_LENGTH;


/*
 * Obfuscate data in buf of length size with contents read from the installer.
 */
static int obfuscate(int8_t *const buf, const int32_t size, FILE *installer)
{
        int8_t* obf = (int8_t*)malloc(sizeof(int8_t)*size);
	if(!obf){
		printf("Can't allocate buffer for obfuscation data.\n");
		return -1;
	}
	size_t tmp_size = size;
	if(fread(obf, sizeof(int8_t), size, installer) != tmp_size){
		printf("Can't read obfuscation data.\n");
		free(obf);
		return -1;
	}
	for(int32_t idx = 0; idx < size; ++idx){
		buf[idx] ^= obf[idx] ^ 0xA5;
	}
	free(obf);
	return 0;

}

/*
 * Writes contents of file named name (length of the name is name_len)
 *   from buffer buf of length src_size to file dest.
 * The basic structure is the following:
 *   One or more records with this structure:
 *     Name length      - 32bits int
 *     Data length      - 32bits int
 *     Source file name - null terminated string
 *     Data             - Data length bytes
 *   The last record has zeros in both lengths.
 */
static int write_named_file(const int8_t *buf, const int32_t src_size, FILE *dest,
		     const char *name, const int32_t name_len, uint8_t sums[])
{
	
		if(fwrite(&name_len, sizeof(name_len), 1, dest) != 1){
			printf("Problem writing name length.");
			return -1;
		}
		if(fwrite(&src_size, sizeof(int32_t), 1, dest) != 1){
			printf("Problem writing data length.");
			return -1;		
		}
		// To avoid signed/unsigned mix in the conditions
		size_t tmp_size = name_len;
		if(fwrite(name, sizeof(int8_t), name_len, dest) != tmp_size){
			printf("Problem writing file data (%s).", name);
			return -1;
		}
		tmp_size = src_size;
		if(fwrite(buf, sizeof(int8_t), src_size, dest) != tmp_size){
			printf("Problem writing file data.");
			return -1;		
		}
		if(fwrite(sums, sizeof(uint8_t), sums_len, dest) != sums_len){
			printf("Problem writing checksum.");
			return -1;		
		}
		return 0;
}

static int32_t file_size(const char *fname)
{
	struct stat file_info;
	if(stat(fname, &file_info)){
		printf("File '%s' not found.", fname);
		return -1;
	}
	int32_t size = file_info.st_size;
	if(size != file_info.st_size){
		printf("File '%s' is too big.", fname);
		return -1;
	}
	return size;
}

static const char *get_base_name(const char *fname){
       	char *last_slash = rindex(fname, '/');
	const char* base_name = last_slash ? (last_slash + 1) : fname;
	const size_t max_name_len = 1024;
       	size_t name_len = strnlen(base_name, max_name_len);
	if(name_len == max_name_len){
		printf("The file name '%s' seems to be ridiculously long...", base_name);
		return NULL;
	}
	return base_name;
}

/*
 * Read contents of data in file src (data size is size);
 *   name of the source file is base name. Data will be
 *   obfuscated using contents of the installer file
 *   and the informations and data will be written
 *   into file dest. 
 */
static int process_file(FILE *src, int32_t size, const char *base_name,
		        FILE* dest, FILE *installer)
{
	int8_t* buf = NULL;
	buf = (int8_t*)malloc(size);
	if(!buf){
		printf("Failed to alocate buffer.\n");
		return -1;
	}
	size_t tmp_size = size;
	if(fread(buf, sizeof(int8_t), size, src) != tmp_size){
		printf("Problem reading file '%s'.\n", base_name);
		free(buf);
		return -1;
	}
	
	uint8_t sums[sums_len];
	sha1sum((uint8_t*)buf, size, (uint32_t*)sums);
	md5sum((uint8_t*)buf, size, (uint32_t*)(&sums[SHA_DIGEST_LENGTH]));
	if(obfuscate(buf, size, installer) != 0){
		free(buf);
		return -1;
	}
	
	size_t name_len = strlen(base_name) + 1;
	write_named_file(buf, size, dest, base_name, name_len, sums);
        free(buf);
	return 0;
}

/*
 * Append file named name to blob. Installer is used for data obfuscation.
 */
static int append_file(FILE *installer, FILE *blob, const char* name)
{
	int32_t size = file_size(name);
	if(size < 0){
		return -1;
	}
	const char *base_name = get_base_name(name);
	if(!base_name){
		return -1;
	}

	FILE *src = NULL;
	if((src = fopen(name, "rb")) == NULL){
		printf("Couldn't open file '%s' for read.\n", name);
		return -1;
	}
	int res = process_file(src, size, base_name, blob, installer);

	fclose(src);
	return res;
}

/*
 * Deobfuscates data in the buffer using contents of installer
 *   and writes them to a file at destination directory.
 */
static int process_buffer(int8_t* buffer, int32_t fname_len, int32_t data_len, FILE* installer, const char* destination)
{
	if(!destination){
		printf("Destination directory must be non-NULL.\n");
		return -1;
	}
	if(obfuscate(buffer + fname_len, data_len, installer) != 0){
		printf("Problem deobfuscating buffer.\n");
		return -1;
	}

	uint8_t sums[sums_len];
	sha1sum((uint8_t*)buffer + fname_len, data_len, (uint32_t*)sums);
	md5sum((uint8_t*)buffer + fname_len, data_len, (uint32_t*)(&sums[SHA_DIGEST_LENGTH]));
	uint8_t cmp = 0;
	uint8_t* checksum = (uint8_t*)buffer + fname_len + data_len;
	for(unsigned int i = 0; i < sums_len; ++i){
		cmp |= sums[i] ^ checksum[i];
	}
	if(cmp != 0){
		printf("Extracted file checksums do not match.\n");
		return -1;
	}

	char* dest;
	if(asprintf(&dest, "%s/%s", destination, buffer) < 0){
		printf("Can't allocate buffer for the output file name.\n");
		return -1;
	}

	FILE* dest_file;
	if(!(dest_file = fopen(dest, "wb"))){
		printf("Problem opening file '%s' for writing.\n", dest);
		free(dest);
		return -1;
	}
	if(fwrite(buffer + fname_len, sizeof(int8_t), data_len, dest_file)
	   != (size_t)data_len){
		printf("Can't write to the output file '%s'.\n", dest);
		free(dest);
		fclose(dest_file);
		return -1;
	}
        fclose(dest_file);
	free(dest);
	return 0;
}

/*
 * Extracts contents of blob, using installer for deobfuscation.
 */
static int extract_files(FILE* blob, FILE* installer, const char* destination)
{
	while(!feof(blob)){
		int32_t fname_size;
		int32_t data_len;

		if((fread(&fname_size, sizeof(fname_size), 1, blob) != 1) ||
		   (fread(&data_len, sizeof(data_len), 1, blob) != 1)){
			printf("Problem reading blob.\n");
			return -1;
		}
		size_t len = fname_size + data_len;
		if(len == 0){
			break;
		}
		// So checksums are extracted too...
		len += sums_len;
		int8_t* buffer = malloc(len);
		if(!buffer){
			printf("Problem allocating buffer for data.\n");
			return -1;
		}

		if(fread(buffer, sizeof(int8_t), len, blob) != len){
			printf("Problem reading data from blob.\n");
                	free(buffer);
			return -1;
		}
		printf("Going to extract file '%s' (%d bytes long).\n", buffer, data_len);
		process_buffer(buffer, fname_size, data_len, installer, destination);
		free(buffer);
	}
	return 0;
}

static int get_file_checksums(FILE* f, uint8_t sums[])
{
	const size_t BUF_LEN = 4096;
	uint8_t buffer[BUF_LEN];

	while(true){
		size_t read;
		read = fread(buffer, sizeof(uint8_t), BUF_LEN, f);
		if(read > 0){
			sha1sum(buffer, read, (uint32_t*)(&sums[0]));
			md5sum(buffer, read, (uint32_t*)(&sums[SHA_DIGEST_LENGTH]));
		}else{
			break;
		}
	}

	fseek(f, 0L, SEEK_SET);
	return 0;
}

static FILE* find_blob(const char *installer_name)
{
	FILE* installer;
	if(!(installer = fopen(installer_name, "rb"))){
		printf("Can't open file '%s' for reading.\n", installer_name);
		return NULL;
	}

	uint8_t installer_sums[SHA_DIGEST_LENGTH+MD5_DIGEST_LENGTH];
        if(get_file_checksums(installer, installer_sums) != 0){
		printf("Problem computing installer checksums.");
		return NULL;
	}

	glob_t blobs;
	blobs.gl_offs = 0;
	FILE* res = NULL;
	char *pattern = ltr_int_get_data_path("blob_*.bin");
	if(glob(pattern, GLOB_NOSORT, NULL, &blobs) != GLOB_NOMATCH){
		for(size_t i = 0; i < blobs.gl_pathc; ++i){
			res = fopen(blobs.gl_pathv[i], "rb");
			if(res){
				uint8_t sums[SHA_DIGEST_LENGTH + MD5_DIGEST_LENGTH];
				if(fread(sums, sizeof(uint8_t), SHA_DIGEST_LENGTH + MD5_DIGEST_LENGTH, res) ==
						SHA_DIGEST_LENGTH + MD5_DIGEST_LENGTH){
					uint8_t sum = 0;
					for(size_t j = 0; j < SHA_DIGEST_LENGTH + MD5_DIGEST_LENGTH; ++j){
						sum |= installer_sums[j] ^ sums[j];
					}
					if(sum == 0){
						free(pattern);
						globfree(&blobs);
						return res;
					}

				}
				fclose(res);
				res = NULL;
			}
		}
	}
	free(pattern);
	globfree(&blobs);
	return NULL;
}


/*
 * Extract contents of the blob using inst contents for deobfuscation.
 */
int extract_blob(const char *inst, const char* destination)
{
	
	FILE *f, *installer;
	if(!(installer = fopen(inst, "rb"))){
		printf("Can't open file '%s' for reading.\n", inst);
		return -1;
	}
	if(!(f = find_blob(inst))){
		printf("Can't find a blob matching the installer.\n");
		fclose(installer);
		return -1;
	}
        
	extract_files(f, installer, destination);

	fclose(f);
	fclose(installer);
	return 0;
}

/*
 * Add the last record marker (both lengths zero)
 */
static int finish_blob(FILE *blob){
	int32_t zeros[2] = {0};
	if(fwrite(zeros, sizeof(int32_t), 2, blob) != 2){
		printf("Problem finishing blob.");
		return -1;
	}
	return 0;
}


/*
 * From sources creates blob named name using inst's contents for obfuscation
 */
int create_blob(const char *name, const char *sources[], const char *inst)
{
	FILE *blob, *installer;
	if(!(installer = fopen(inst, "rb"))){
		printf("Can't open file '%s' for reading.\n", inst);
		return -1;
	}
	if(!(blob = fopen(name, "wb"))){
		printf("Can't open file '%s' for writing.\n", name);
		fclose(installer);
		return -1;
	}

	uint8_t sums[SHA_DIGEST_LENGTH + MD5_DIGEST_LENGTH];
        if(get_file_checksums(installer, sums) != 0){
		printf("Problem computing installer checksums.");
		return -1;
	}

	if(fwrite(sums, sizeof(uint8_t), sums_len, blob) != sums_len){
		printf("Problem writing checksums to blob.");
		return -1;
	}

        int res = 0;
	int idx = 0;
	while(sources[idx] && (res == 0)){
		res = res || append_file(installer, blob, sources[idx]);
		++idx;
	}
	res = res || finish_blob(blob);

	fclose(installer);
	fclose(blob);
	return res;
}



