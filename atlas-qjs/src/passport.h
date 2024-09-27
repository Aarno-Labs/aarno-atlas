#ifndef PASSPORT_H
#define PASSPORT_H

#ifdef SEDIMENT


  // Pass SEDIMENT info from C++ to C
  typedef struct {
    uint8_t *passport;
    size_t passport_size;
    char *device_id;
  } PassportBytes;

extern int ProverRun(PassportBytes *passport_bytes,
                      const char config_file[],
                      const char exe[],
                      const int enable_ssl,
                      const char ssl_cert_file[],
                      const char ssl_key_file[],
                      const int ra_log_level);
#endif  // SEDIMENT

#endif // PASSPORT_H
