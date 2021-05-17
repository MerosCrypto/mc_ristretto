#ifndef MC_RISTRETTO_H
#define MC_RISTRETTO_H

#include <stdbool.h>

void reduce_to_scalar(const uint8_t *scalar, uint8_t *res);

bool verify_point(const uint8_t *point);

void add_scalar(const uint8_t *x, const uint8_t *y, uint8_t *res);

void mul_scalar(const uint8_t *x, const uint8_t *y, uint8_t *res);

void add_point(const uint8_t *x, const uint8_t *y, uint8_t *res);

void mul_point_by_scalar(const uint8_t *x, const uint8_t *y, uint8_t *res);

void to_point(const uint8_t *scalar, uint8_t *res);

void sign(const uint8_t *scalar,
          const uint8_t *nonce,
          const uint8_t *msg,
          uint32_t msg_length,
          uint8_t *res);

bool verify(const uint8_t *point, const uint8_t *msg, uint32_t msg_length, const uint8_t *sig);

#endif
