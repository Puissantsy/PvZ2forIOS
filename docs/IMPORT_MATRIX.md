# PvZ2 1.5.252752 Android import inventory

Source: `lib/armeabi-v7a/libPVZ2.so` from the original PvZ2 1.5.252752 APK.

Total undefined ELF symbols: **328**.

The compatibility layer should be developed by subsystem rather than reactively implementing one symbol per probe run.

## GLES — 79

`glActiveTexture`, `glAlphaFunc`, `glAttachShader`, `glBindAttribLocation`, `glBindFramebuffer`, `glBindFramebufferOES`, `glBindTexture`, `glBlendFunc`, `glCheckFramebufferStatus`, `glCheckFramebufferStatusOES`, `glClear`, `glClearColor`, `glClearDepthf`, `glClientActiveTexture`, `glColorMask`, `glColorPointer`, `glCompileShader`, `glCompressedTexImage2D`, `glCreateProgram`, `glCreateShader`, `glCullFace`, `glDeleteFramebuffers`, `glDeleteFramebuffersOES`, `glDeleteProgram`, `glDeleteShader`, `glDeleteTextures`, `glDepthFunc`, `glDepthMask`, `glDepthRangef`, `glDisable`, `glDisableClientState`, `glDisableVertexAttribArray`, `glDrawArrays`, `glDrawElements`, `glEnable`, `glEnableClientState`, `glEnableVertexAttribArray`, `glFramebufferTexture2D`, `glFramebufferTexture2DOES`, `glFrontFace`, `glGenFramebuffers`, `glGenFramebuffersOES`, `glGenTextures`, `glGetError`, `glGetIntegerv`, `glGetProgramInfoLog`, `glGetProgramiv`, `glGetShaderInfoLog`, `glGetShaderiv`, `glGetString`, `glGetUniformLocation`, `glIsProgram`, `glIsShader`, `glIsTexture`, `glLineWidth`, `glLinkProgram`, `glLoadIdentity`, `glLoadMatrixf`, `glMatrixMode`, `glNormalPointer`, `glPixelStorei`, `glPopMatrix`, `glPushMatrix`, `glScalef`, `glScissor`, `glShadeModel`, `glShaderSource`, `glTexCoordPointer`, `glTexEnvf`, `glTexImage2D`, `glTexParameteri`, `glTexSubImage2D`, `glUniform1i`, `glUniform4fv`, `glUniformMatrix4fv`, `glUseProgram`, `glVertexAttribPointer`, `glVertexPointer`, `glViewport`

## OpenSL — 6

`SL_IID_ANDROIDCONFIGURATION`, `SL_IID_AUDIOIODEVICECAPABILITIES`, `SL_IID_BUFFERQUEUE`, `SL_IID_ENGINE`, `SL_IID_PLAY`, `slCreateEngine`

## pthread / semaphore / scheduler — 49

`pthread_attr_destroy`, `pthread_attr_getschedparam`, `pthread_attr_getstack`, `pthread_attr_init`, `pthread_attr_setdetachstate`, `pthread_attr_setschedparam`, `pthread_attr_setschedpolicy`, `pthread_attr_setstack`, `pthread_attr_setstacksize`, `pthread_cond_broadcast`, `pthread_cond_destroy`, `pthread_cond_init`, `pthread_cond_signal`, `pthread_cond_timedwait`, `pthread_cond_wait`, `pthread_condattr_destroy`, `pthread_condattr_init`, `pthread_create`, `pthread_detach`, `pthread_exit`, `pthread_getattr_np`, `pthread_getschedparam`, `pthread_getspecific`, `pthread_join`, `pthread_key_create`, `pthread_key_delete`, `pthread_mutex_destroy`, `pthread_mutex_init`, `pthread_mutex_lock`, `pthread_mutex_trylock`, `pthread_mutex_unlock`, `pthread_mutexattr_destroy`, `pthread_mutexattr_init`, `pthread_mutexattr_setpshared`, `pthread_mutexattr_settype`, `pthread_once`, `pthread_self`, `pthread_setschedparam`, `pthread_setspecific`, `sched_get_priority_max`, `sched_get_priority_min`, `sched_yield`, `sem_destroy`, `sem_getvalue`, `sem_init`, `sem_post`, `sem_timedwait`, `sem_trywait`, `sem_wait`

## zlib — 13

`adler32`, `compress`, `crc32`, `deflate`, `deflateEnd`, `deflateInit2_`, `deflateInit_`, `deflateReset`, `inflate`, `inflateEnd`, `inflateInit_`, `inflateReset`, `uncompress`

## math — 25

`acos`, `acosf`, `asinf`, `atan2`, `atan2f`, `ceil`, `ceilf`, `cos`, `cosf`, `exp`, `fabs`, `floor`, `floorf`, `fmod`, `fmodf`, `log10`, `modf`, `pow`, `powf`, `sin`, `sinf`, `sqrt`, `sqrtf`, `tan`, `tanf`

## wide-char / locale — 37

`btowc`, `fwide`, `getwc`, `iswalnum`, `iswctype`, `iswspace`, `mbrtowc`, `putwc`, `setlocale`, `strcoll`, `strxfrm`, `swscanf`, `towlower`, `towupper`, `ungetwc`, `vswprintf`, `wcrtomb`, `wcschr`, `wcscmp`, `wcscoll`, `wcscpy`, `wcscspn`, `wcsftime`, `wcslen`, `wcsncmp`, `wcsncpy`, `wcsspn`, `wcstol`, `wcstombs`, `wcsxfrm`, `wctob`, `wctype`, `wmemchr`, `wmemcmp`, `wmemcpy`, `wmemmove`, `wmemset`

## file / POSIX / time — 39

`access`, `asctime`, `clock`, `clock_gettime`, `close`, `closedir`, `fnmatch`, `fstat`, `fsync`, `ftruncate`, `getcwd`, `getenv`, `gettimeofday`, `gmtime`, `ioctl`, `localtime`, `localtime_r`, `lseek`, `mkdir`, `mktemp`, `mktime`, `nanosleep`, `open`, `opendir`, `poll`, `prctl`, `read`, `readdir`, `readdir_r`, `stat`, `strftime`, `strptime`, `syscall`, `sysconf`, `time`, `unlink`, `usleep`, `write`, `writev`

## libc / string / memory / stdio — 66

`__aeabi_memcpy`, `__aeabi_memmove`, `__aeabi_memset`, `abort`, `atoi`, `atol`, `exit`, `fclose`, `fdopen`, `feof`, `ferror`, `fflush`, `fgetc`, `fgets`, `fopen`, `fprintf`, `fputc`, `fputs`, `fread`, `free`, `fscanf`, `fseek`, `fsetpos`, `ftell`, `fwrite`, `getc`, `longjmp`, `lrand48`, `malloc`, `memalign`, `memchr`, `memcmp`, `memcpy`, `memmove`, `memset`, `printf`, `putc`, `puts`, `qsort`, `raise`, `realloc`, `setjmp`, `setvbuf`, `snprintf`, `sprintf`, `srand48`, `sscanf`, `strcasecmp`, `strcat`, `strchr`, `strcmp`, `strcpy`, `strerror`, `strlen`, `strncasecmp`, `strncat`, `strncmp`, `strncpy`, `strstr`, `strtod`, `strtok`, `strtol`, `strtoul`, `ungetc`, `vsnprintf`, `vsprintf`

## Android runtime / globals — 14

`__android_log_assert`, `__android_log_print`, `__android_log_write`, `__cxa_atexit`, `__cxa_finalize`, `__errno`, `__gnu_Unwind_Find_exidx`, `__sF`, `__stack_chk_fail`, `__stack_chk_guard`, `_ctype_`, `_tolower_tab_`, `_toupper_tab_`, `ptrace`
