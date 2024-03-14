#ifndef _EXTRACT__H
#define _EXTRACT__H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * From sources creates blob named name using inst's contents for obfuscation
 */
int create_blob(const char *name, const char *sources[], const char *inst);

/*
 * Extract contents of the blob using inst contents for deobfuscation.
 */
int extract_blob(const char *inst, const char* destination);

char *get_blob_name(const char *installer_name);

#ifdef __cplusplus
}
#endif

#endif
