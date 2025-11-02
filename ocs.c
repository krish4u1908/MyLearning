/* ocs_dynamic_builder.c
 *
 * Generic OCS-like Diameter simulator — dynamic CCA builder.
 *
 * Build:
 *   gcc -O2 -o ocs_dynamic_builder ocs_dynamic_builder.c -lpthread
 *
 * Usage:
 *   sudo ./ocs_dynamic_builder [-p port] [-H origin-host] [-R origin-realm]
 *       [-r top_result_code] [-m mscc_result_code] [-g max_grant_bytes]
 *       [-d default_grant_bytes] [-v]
 *
 * Example:
 *   sudo ./ocs_dynamic_builder -p 3868 -H ocs.test -R example.com -r 2001 -m 4012 -g 33554432 -d 1048576 -v
 *
 * Notes:
 * - Builds CCAs on-the-fly (no templates).
 * - MSCC (Multiple-Services-Credit-Control) AVP code: 456 (grouped).
 * - Copies Session-Id (263) and Subscription-Id-Data (444) from CCR to CCA.
 * - Extracts Requested-Service-Unit Total-Octets (421) from top-level or inside MSCC/Requested-Service-Unit.
 * - Puts Result-Code (top-level) and optionally MSCC-level result code (inside each MSCC grouped AVP).
 */

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 3868
#define DEFAULT_ORIGIN_HOST "ocs.local"
#define DEFAULT_ORIGIN_REALM "local.realm"
#define DEFAULT_MAX_GRANT (1024ULL*1024ULL*16ULL) /* 16 MB */
#define DEFAULT_GRANT (1024ULL*1024ULL) /* 1 MB */
#define MAX_PACKET_SIZE 131072

/* Diameter command codes */
enum {
    CMD_CER = 257,
    CMD_CEA = 257,
    CMD_CC  = 272,
    CMD_CCA = 272,
    CMD_DWR = 280,
    CMD_DWA = 280,
    CMD_DPR = 282,
    CMD_DPA = 282
};

/* AVP Codes */
enum {
    AVP_SESSION_ID = 263,
    AVP_ORIGIN_HOST = 264,
    AVP_RESULT_CODE = 268,
    AVP_HOST_IP_ADDRESS = 257,
    AVP_AUTH_APPLICATION_ID = 258,
    AVP_VENDOR_ID = 266,
    AVP_FIRMWARE_ID = 267,
    AVP_ORIGIN_STATE_ID = 278,
    AVP_ORIGIN_REALM = 296,
    AVP_SUBSCRIPTION_ID = 443,
    AVP_SUBSCRIPTION_ID_TYPE = 450,
    AVP_SUBSCRIPTION_ID_DATA = 444,
    AVP_CC_REQUEST_TYPE = 416,
    AVP_CC_REQUEST_NUMBER = 415,
    AVP_REQUESTED_SERVICE_UNIT = 437,
    AVP_GRANTED_SERVICE_UNIT = 431,
    AVP_TOTAL_OCTETS = 421,
    AVP_MULTIPLE_SERVICES_CREDIT_CONTROL = 456,
    AVP_PRODUCT_NAME = 269
};

/* globals configured from CLI */
static char origin_host[256] = DEFAULT_ORIGIN_HOST;
static char origin_realm[256] = DEFAULT_ORIGIN_REALM;
static uint32_t top_result_code = 2001;
static uint32_t mscc_result_code = 0; /* 0 => use top_result_code */
static uint64_t max_grant_bytes = DEFAULT_MAX_GRANT;
static uint64_t default_grant_bytes = DEFAULT_GRANT;
static int verbose = 0;

/* Helper: read exactly n bytes */
static int read_n(int fd, void *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, (char*)buf + off, n - off);
        if (r == 0) return 0; /* EOF */
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += r;
    }
    return 1;
}

/* Helper: append raw data into dynamic buffer */
static int append_raw(uint8_t **buf, size_t *len, const uint8_t *data, size_t data_len) {
    uint8_t *nb = realloc(*buf, *len + data_len);
    if (!nb) return -1;
    memcpy(nb + *len, data, data_len);
    *buf = nb;
    *len += data_len;
    return 0;
}

/* Build AVP header (code, flags, vendor optional, then data and padding).
   flags: usual 0x40 for 'M' (must), or other bits. vendor = 0 if not used.
*/
static int append_avp(uint8_t **buf, size_t *len, uint32_t code, uint8_t flags, uint32_t vendor, const uint8_t *data, size_t data_len) {
    size_t header_len = 8 + ((flags & 0x80) ? 4 : 0);
    uint32_t avp_len = header_len + (uint32_t)data_len;
    uint32_t pad = (4 - (avp_len % 4)) % 4;
    uint8_t hdr[12];
    uint32_t cbe = htonl(code); memcpy(hdr, &cbe, 4);
    hdr[4] = flags;
    hdr[5] = (avp_len >> 16) & 0xff;
    hdr[6] = (avp_len >> 8) & 0xff;
    hdr[7] = (avp_len) & 0xff;
    size_t off = 8;
    if (flags & 0x80) { uint32_t vbe = htonl(vendor); memcpy(hdr+off, &vbe, 4); off += 4; }
    if (append_raw(buf, len, hdr, off) != 0) return -1;
    if (data_len) if (append_raw(buf, len, data, data_len) != 0) return -1;
    if (pad) {
        uint8_t z[4] = {0,0,0,0};
        if (append_raw(buf, len, z, pad) != 0) return -1;
    }
    return 0;
}

/* Convenience: append utf8 string AVP */
static int append_avp_string(uint8_t **buf, size_t *len, uint32_t code, const char *s) {
    return append_avp(buf, len, code, 0x40, 0, (const uint8_t*)s, strlen(s));
}

/* Convenience: append utf8 string AVP */
static int append_avp_string_optional(uint8_t **buf, size_t *len, uint32_t code, const char *s) {
    return append_avp(buf, len, code, 0x00, 0, (const uint8_t*)s, strlen(s));
}

/* Convenience: append uint32 AVP */
static int append_avp_u32(uint8_t **buf, size_t *len, uint32_t code, uint32_t val) {
    uint32_t vbe = htonl(val);
    return append_avp(buf, len, code, 0x40, 0, (const uint8_t*)&vbe, 4);
}

/* Parse a single AVP header at ptr with available buflen.
   Returns consumed bytes including padding, and fills out code, flags, len24 (value length includes header), vendor if present.
   On error returns 0.
*/
static size_t parse_avp_header(const uint8_t *ptr, size_t buflen, uint32_t *out_code, uint8_t *out_flags, uint32_t *out_len24, uint32_t *out_vendor) {
    if (buflen < 8) return 0;
    uint32_t code = ntohl(*(uint32_t*)ptr);
    uint8_t flags = ptr[4];
    uint32_t len24 = ((uint32_t)ptr[5] << 16) | ((uint32_t)ptr[6] << 8) | (uint32_t)ptr[7];
    if (len24 < 8 || len24 > buflen) return 0;
    size_t header_len = 8;
    uint32_t vendor = 0;
    if (flags & 0x80) {
        if (buflen < 12) return 0;
        vendor = ntohl(*(uint32_t*)(ptr + 8));
        header_len += 4;
        if (len24 < header_len) return 0;
    }
    size_t pad = (4 - (len24 % 4)) % 4;
    size_t total = len24 + pad;
    *out_code = code; *out_flags = flags; *out_len24 = len24; *out_vendor = vendor;
    return total;
}

/* Helpers to extract inner data */
static uint32_t avp_u32_value(const uint8_t *avp_ptr, uint32_t len24) {
    uint8_t flags = avp_ptr[4];
    size_t header_len = 8 + ((flags & 0x80) ? 4 : 0);
    if (len24 < header_len + 4) return 0;
    uint32_t v; memcpy(&v, avp_ptr + header_len, 4); return ntohl(v);
}
static void avp_string_value(const uint8_t *avp_ptr, uint32_t len24, char *out, size_t outlen) {
    uint8_t flags = avp_ptr[4];
    size_t header_len = 8 + ((flags & 0x80) ? 4 : 0);
    size_t dlen = len24 - header_len;
    if (dlen >= outlen) dlen = outlen - 1;
    if (dlen > 0) memcpy(out, avp_ptr + header_len, dlen);
    out[dlen] = '\0';
}

/* Find Total-Octets (421) inside a grouped AVP (like Requested-Service-Unit or Granted-Service-Unit).
   avp_ptr points at the start of grouped AVP header; len24 is that AVP's length (without padding).
   Returns found u32 value or 0 if not found.
*/
static uint64_t find_total_octets_in_group(const uint8_t *avp_ptr, uint32_t len24) {
    uint8_t flags = avp_ptr[4];
    size_t header_len = 8 + ((flags & 0x80) ? 4 : 0);
    if (len24 <= header_len) return 0;
    const uint8_t *inner = avp_ptr + header_len;
    size_t inner_len = len24 - header_len;
    size_t off = 0;
    while (off < inner_len) {
        uint32_t code; uint8_t f; uint32_t ilen; uint32_t vendor;
        size_t cons = parse_avp_header(inner + off, inner_len - off, &code, &f, &ilen, &vendor);
        if (!cons) break;
        if (code == AVP_TOTAL_OCTETS) {
            if (ilen >= (8 + ((f & 0x80) ? 4 : 0) + 4)) {
                uint32_t v; memcpy(&v, inner + off + 8 + ((f & 0x80) ? 4 : 0), 4); v = ntohl(v);
                return (uint64_t)v;
            }
        }
        off += cons;
    }
    return 0;
}

/* Extract Subscription-Id Data (444) from grouped Subscription-Id AVP (443) */
static int extract_subscription_data(const uint8_t *avp_ptr, uint32_t len24, char *out, size_t outlen) {
    uint8_t flags = avp_ptr[4];
    size_t header_len = 8 + ((flags & 0x80) ? 4 : 0);
    if (len24 <= header_len) return 0;
    const uint8_t *inner = avp_ptr + header_len;
    size_t inner_len = len24 - header_len;
    size_t off = 0;
    while (off < inner_len) {
        uint32_t code; uint8_t f; uint32_t ilen; uint32_t vendor;
        size_t cons = parse_avp_header(inner + off, inner_len - off, &code, &f, &ilen, &vendor);
        if (!cons) break;
        if (code == AVP_SUBSCRIPTION_ID_DATA) {
            size_t dhead = 8 + ((f & 0x80) ? 4 : 0);
            size_t dlen = ilen - dhead;
            if (dlen >= outlen) dlen = outlen - 1;
            if (dlen > 0) memcpy(out, inner + off + dhead, dlen);
            out[dlen] = '\0';
            return 1;
        }
        off += cons;
    }
    return 0;
}

/* Request context extracted from CCR */
typedef struct {
    char session_id[512]; int has_session;
    char sub_data[256]; int has_sub;
    uint64_t requested_total_octets; /* from top-level Requested-Service-Unit or from MSCC inner requested */
    uint32_t cc_request_type;
    uint32_t cc_request_number;
} req_ctx_t;

/* Parse CCR body (AVPs) to fill req_ctx_t.
   We search:
    - Session-Id (263)
    - Subscription-Id (443) -> inner 444
    - Requested-Service-Unit (437) top-level -> inner Total-Octets 421
    - Multiple-Services-Credit-Control (456) grouped: look inside for Requested-Service-Unit and Result-Code if needed.
*/
static void parse_ccr_body(const uint8_t *body, size_t body_len, req_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    size_t off = 0;
    while (off < body_len) {
        uint32_t code; uint8_t flags; uint32_t len24; uint32_t vendor;
        size_t cons = parse_avp_header(body + off, body_len - off, &code, &flags, &len24, &vendor);
        if (!cons) break;
        const uint8_t *avp_ptr = body + off;
        if (code == AVP_SESSION_ID) {
            avp_string_value(avp_ptr, len24, ctx->session_id, sizeof(ctx->session_id));
            ctx->has_session = 1;
        } else if (code == AVP_SUBSCRIPTION_ID) {
            if (extract_subscription_data(avp_ptr, len24, ctx->sub_data, sizeof(ctx->sub_data))) ctx->has_sub = 1;
        } else if (code == AVP_REQUESTED_SERVICE_UNIT) {
            uint64_t v = find_total_octets_in_group(avp_ptr, len24);
            if (v) ctx->requested_total_octets = v;
        } else if (code == AVP_MULTIPLE_SERVICES_CREDIT_CONTROL) {
            /* look inside grouped MSCC for Requested-Service-Unit */
            /* header_len for this AVP: */
            uint8_t f = avp_ptr[4];
            size_t header_len = 8 + ((f & 0x80) ? 4 : 0);
            if (len24 > header_len) {
                const uint8_t *inner = avp_ptr + header_len;
                size_t inner_len = len24 - header_len;
                size_t ioff = 0;
                while (ioff < inner_len) {
                    uint32_t ic; uint8_t iflags; uint32_t ilen; uint32_t ivendor;
                    size_t icons = parse_avp_header(inner + ioff, inner_len - ioff, &ic, &iflags, &ilen, &ivendor);
                    if (!icons) break;
                    if (ic == AVP_REQUESTED_SERVICE_UNIT) {
                        uint64_t v = find_total_octets_in_group(inner + ioff, ilen);
                        if (v) ctx->requested_total_octets = v;
                    }
                    if (ic == AVP_SUBSCRIPTION_ID) {
                        char s[256];
                        if (extract_subscription_data(inner + ioff, ilen, s, sizeof(s))) {
                            strncpy(ctx->sub_data, s, sizeof(ctx->sub_data)-1);
                            ctx->has_sub = 1;
                        }
                    }
                    ioff += icons;
                }
            }
        } else if (code == AVP_CC_REQUEST_TYPE) {
            ctx->cc_request_type = avp_u32_value(avp_ptr, len24);
        } else if (code == AVP_CC_REQUEST_NUMBER) {
            ctx->cc_request_number = avp_u32_value(avp_ptr, len24);
        }
        off += cons;
    }
}

/* Build Granted-Service-Unit grouped AVP with Total-Octets = grant */
static int append_granted_service_unit(uint8_t **buf, size_t *len, uint64_t grant) {
    uint32_t g32 = (grant > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : (uint32_t)grant;
    /* inner Total-Octets AVP */
    uint32_t vbe = htonl(g32);
    if (append_avp(buf, len, AVP_TOTAL_OCTETS, 0x40, 0, (const uint8_t*)&vbe, 4) != 0) return -1;
    /* Now wrap inner bytes into Granted-Service-Unit grouped AVP (431) */
    /* To do that, we need to extract inner bytes we just added — simpler approach: build inner in temporary buffer */
    /* But we already appended inner to buf; easier: create temp inner and then append as grouped */
    return 0; /* unused in this code path because we build grouped using temp buffer below */
}

/* Build Granted-Service-Unit grouped AVP using temporary inner */
static int append_granted_service_unit_group(uint8_t **buf, size_t *len, uint64_t grant) {
    uint32_t g32 = (grant > 0xFFFFFFFFULL) ? 0xFFFFFFFFU : (uint32_t)grant;
    uint8_t inner_hdr[12];
    uint8_t total_octets_be[4];
    uint32_t code_be = htonl(AVP_TOTAL_OCTETS);
    memcpy(inner_hdr, &code_be, 4);
    inner_hdr[4] = 0x40;
    /* length = 8 + 4 = 12 (no vendor) */
    inner_hdr[5] = 0; inner_hdr[6] = 0; inner_hdr[7] = 12;
    uint32_t gbe = htonl(g32); memcpy(total_octets_be, &gbe, 4);
    /* inner bytes = inner_hdr (12) + total_octets (4) ? careful: inner_hdr already contains the length and header only; data follows */
    /* But for a standard AVP we should write header then data (we set header len 12 including header). Simpler: build inner properly with append_avp helper on temp */
    uint8_t *tmp = NULL; size_t tmp_len = 0;
    if (append_avp(&tmp, &tmp_len, AVP_TOTAL_OCTETS, 0x40, 0, (const uint8_t*)&gbe, 4) != 0) { free(tmp); return -1; }
    /* now wrap tmp as GRANTED-SERVICE-UNIT grouped */
    if (append_avp(buf, len, AVP_GRANTED_SERVICE_UNIT, 0x40, 0, tmp, tmp_len) != 0) { free(tmp); return -1; }
    free(tmp);
    return 0;
}

/* Build MSCC grouped AVP:
   Put inside:
     - Granted-Service-Unit (with Total-Octets)
     - optional Result-Code (if mscc_result_code set)
   We will also preserve subscription info if available from request (build inner Subscription-Id)
*/
static int append_mscc_group(uint8_t **buf, size_t *len, const req_ctx_t *ctx) {
    uint8_t *inner = NULL; size_t inner_len = 0;
    /* If subscription present, include Subscription-Id grouped (type=1, data=IMSI) */
    if (ctx->has_sub) {
        /* Subscription-Id-Type */
        if (append_avp(&inner, &inner_len, AVP_SUBSCRIPTION_ID_TYPE, 0x40, 0, (const uint8_t*)&(uint32_t){htonl(1)}, 4) != 0) { free(inner); return -1; }
        /* Subscription-Id-Data */
        if (append_avp(&inner, &inner_len, AVP_SUBSCRIPTION_ID_DATA, 0x40, 0, (const uint8_t*)ctx->sub_data, strlen(ctx->sub_data)) != 0) { free(inner); return -1; }
        /* Now wrap inner into Subscription-Id grouped (443) */
        /* But append_avp expects data pointer + data_len; inner currently contains raw AVPs; put them in subscription group */
        uint8_t *subgrp = NULL; size_t subgrp_len = 0;
        if (append_avp(&subgrp, &subgrp_len, AVP_SUBSCRIPTION_ID, 0x40, 0, inner, inner_len) != 0) { free(inner); free(subgrp); return -1; }
        /* append subgrp to mscc inner (we'll append everything to mscc_inner later) */
        /* Instead of complicating, we'll build mscc_inner step by step: */
        free(inner); inner = NULL; inner_len = 0;
        /* add subscription group bytes directly to inner */
        if (append_raw(&inner, &inner_len, subgrp, subgrp_len) != 0) { free(subgrp); free(inner); return -1; }
        free(subgrp);
    }
    /* Determine grant amount */
    uint64_t grant = ctx->requested_total_octets ? ctx->requested_total_octets : default_grant_bytes;
    if (grant > max_grant_bytes) grant = max_grant_bytes;
    /* append Granted-Service-Unit grouped AVP */
    if (append_granted_service_unit_group(&inner, &inner_len, grant) != 0) { free(inner); return -1; }
    /* If MSCC result code explicitly set, append it inside MSCC */
    uint32_t rc_inside = mscc_result_code ? mscc_result_code : top_result_code;
    if (rc_inside) {
        if (append_avp_u32(&inner, &inner_len, AVP_RESULT_CODE, rc_inside) != 0) { free(inner); return -1; }
    }
    /* Finally append the MSCC grouped AVP (456) containing inner */
    if (append_avp(buf, len, AVP_MULTIPLE_SERVICES_CREDIT_CONTROL, 0x40, 0, inner, inner_len) != 0) { free(inner); return -1; }
    free(inner);
    return 0;
}

/* Build a CCA from request context */
static uint8_t *build_cca(const req_ctx_t *ctx, uint32_t req_appid, uint32_t req_hbh, uint32_t req_e2e, size_t *out_len) {
    uint8_t *body = NULL; size_t body_len = 0;
    /* Session-Id (copy if present) */
    if (ctx->has_session) append_avp_string(&body, &body_len, AVP_SESSION_ID, ctx->session_id);
    /* Result-Code (top-level) */
    append_avp_u32(&body, &body_len, AVP_RESULT_CODE, top_result_code);
    /* Origin-Host, Origin-Realm */
    append_avp_string(&body, &body_len, AVP_ORIGIN_HOST, origin_host);
    append_avp_string(&body, &body_len, AVP_ORIGIN_REALM, origin_realm);
    /* Auth-Application-Id (AVP 258) - set to 4 as requested */
    append_avp_u32(&body, &body_len, AVP_AUTH_APPLICATION_ID, 4);
    append_avp_u32(&body, &body_len, AVP_CC_REQUEST_TYPE, ctx->cc_request_type);
    append_avp_u32(&body, &body_len, AVP_CC_REQUEST_NUMBER, ctx->cc_request_number);
    if(ctx->cc_request_type==2)
    {

        /* Subscription-Id at top-level? Some deployments expect it inside MSCC; we'll include it inside MSCC as well.
           We'll keep top-level Subscription-Id only if present (helps some clients). */
        if (ctx->has_sub) {
            /* Build Subscription-Id grouped inner */
            uint8_t *sinner = NULL; size_t sinner_len = 0;
            uint32_t t = htonl(1);
            append_avp(&sinner, &sinner_len, AVP_SUBSCRIPTION_ID_TYPE, 0x40, 0, (const uint8_t*)&t, 4);
            append_avp(&sinner, &sinner_len, AVP_SUBSCRIPTION_ID_DATA, 0x40, 0, (const uint8_t*)ctx->sub_data, strlen(ctx->sub_data));
            append_avp(&body, &body_len, AVP_SUBSCRIPTION_ID, 0x40, 0, sinner, sinner_len);
            free(sinner);
        }

        /* Add Multiple-Services-Credit-Control grouped AVP(s). For simplicity build single MSCC group constructed from request */
        append_mscc_group(&body, &body_len, ctx);
    }
    /* Build header */
    uint32_t total_len = (uint32_t)(20 + body_len);
    uint8_t *msg = malloc(total_len);
    if (!msg) { free(body); return NULL; }
    memset(msg, 0, total_len);
    msg[0] = 1;
    msg[1] = (total_len >> 16) & 0xff;
    msg[2] = (total_len >> 8) & 0xff;
    msg[3] = (total_len) & 0xff;
    /* Flags: answers must have R bit cleared (we set 0), preserve P/R bits? simple 0x00 */
    msg[4] = 0x40;
    uint32_t cmd = CMD_CCA;
    msg[5] = (cmd >> 16) & 0xff;
    msg[6] = (cmd >> 8) & 0xff;
    msg[7] = (cmd) & 0xff;
    /* Application-ID: use request appid (so client accepts) */
    uint32_t app_be = htonl(req_appid); memcpy(msg + 8, &app_be, 4);
    /* Hop-by-Hop & End-to-End */
    uint32_t hbh_be = htonl(req_hbh); memcpy(msg + 12, &hbh_be, 4);
    uint32_t e2e_be = htonl(req_e2e); memcpy(msg + 16, &e2e_be, 4);
    memcpy(msg + 20, body, body_len);
    free(body);
    *out_len = total_len;
    return msg;
}
/* Build CEA (Capabilities-Answer) minimal, now with Host-IP-Address, Vendor-Id, Auth-Application-Id */
static uint8_t *build_cea(uint32_t req_hbh, uint32_t req_e2e, size_t *out_len) {
    uint8_t *body = NULL;
    size_t body_len = 0;

    /* Origin-Host, Origin-Realm (keep existing behavior) */
    append_avp_string(&body, &body_len, AVP_ORIGIN_HOST, origin_host);
    append_avp_string(&body, &body_len, AVP_ORIGIN_REALM, origin_realm);
    append_avp_string_optional(&body, &body_len, AVP_PRODUCT_NAME, "OCS Charger");

    /* Host-IP-Address (AVP 257) - store IPv4 address as 4 octets (network order).
       Default: 127.0.0.1. Change this if you want a different address (or expose CLI option).
    */
    {
        uint32_t ip = htonl(0x0aa5d03a); /* 127.0.0.1 */
        uint8_t *ip_ptr=(uint8_t *)malloc(6);
        ip_ptr[0]=0;
        ip_ptr[1]=1;
        memcpy(ip_ptr+2,&ip,4); 
        //append_avp(&body, &body_len, AVP_HOST_IP_ADDRESS, 0x40, 0, (const uint8_t*)&ip, 4);
        append_avp(&body, &body_len, AVP_HOST_IP_ADDRESS, 0x40, 0, ip_ptr, 6);
    }

    /* Vendor-Id (AVP 266) - set to 0 as requested */
    append_avp_u32(&body, &body_len, AVP_VENDOR_ID, 0);
    append_avp_u32(&body, &body_len, AVP_ORIGIN_STATE_ID, 10);
    //append_avp_u32(&body, &body_len, AVP_FIRMWARE_ID, 1000);

    /* Auth-Application-Id (AVP 258) - set to 4 as requested */
    append_avp_u32(&body, &body_len, AVP_AUTH_APPLICATION_ID, 4);

    /* Result-Code */
    append_avp_u32(&body, &body_len, AVP_RESULT_CODE, 2001);

    /* Compose header */
    uint32_t total = (uint32_t)(20 + body_len);
    uint8_t *msg = malloc(total);
    if (!msg) { free(body); return NULL; }
    memset(msg, 0, total);
    msg[0] = 1;
    msg[1] = (total >> 16) & 0xff;
    msg[2] = (total >> 8) & 0xff;
    msg[3] = (total) & 0xff;
    msg[4] = 0x00; /* answer */
    uint32_t cmd = CMD_CER; /* CER/CEA share same command code 257 */
    msg[5] = (cmd >> 16) & 0xff;
    msg[6] = (cmd >> 8) & 0xff;
    msg[7] = (cmd) & 0xff;
    /* Hop-by-Hop & End-to-End */
    uint32_t hbh_be = htonl(req_hbh); memcpy(msg + 12, &hbh_be, 4);
    uint32_t e2e_be = htonl(req_e2e); memcpy(msg + 16, &e2e_be, 4);
    memcpy(msg + 20, body, body_len);
    free(body);
    *out_len = total;
    return msg;
}

/* Build DWA and DPA minimal (reuse CEA builder) */
static uint8_t *build_dwa(uint32_t req_hbh, uint32_t req_e2e, size_t *out_len) {
    return build_cea(req_hbh, req_e2e, out_len);
}
static uint8_t *build_dpa(uint32_t req_hbh, uint32_t req_e2e, size_t *out_len) {
    return build_cea(req_hbh, req_e2e, out_len);
}

/* Connection handler */
static void *conn_handler(void *arg) {
    int fd = (intptr_t)arg;
    if (verbose) fprintf(stderr, "[*] connection handler started fd=%d\n", fd);
    uint8_t hdr[20];
    while (1) {
        int rr = read_n(fd, hdr, 20);
        if (rr == 0) break;
        if (rr < 0) { perror("read"); break; }
        uint32_t len = ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
        if (len < 20 || len > MAX_PACKET_SIZE) { fprintf(stderr, "invalid len %u\n", len); break; }
        uint8_t flags = hdr[4];
        uint32_t cmd = ((uint32_t)hdr[5] << 16) | ((uint32_t)hdr[6] << 8) | (uint32_t)hdr[7];
        uint32_t appid = ntohl(*(uint32_t*)(hdr + 8));
        uint32_t hbh = ntohl(*(uint32_t*)(hdr + 12));
        uint32_t e2e = ntohl(*(uint32_t*)(hdr + 16));
        size_t body_len = len - 20;
        uint8_t *body = NULL;
        if (body_len) {
            body = malloc(body_len);
            if (!body) break;
            if (read_n(fd, body, body_len) <= 0) { free(body); break; }
        }
        if (verbose) fprintf(stderr, "[recv] cmd=%u appid=%u bodylen=%zu\n", cmd, appid, body_len);
        if (cmd == CMD_CER) {
            size_t outlen; uint8_t *resp = build_cea(hbh, e2e, &outlen);
            if (resp) { write(fd, resp, outlen); free(resp); }
            if (body) free(body);
            continue;
        } else if (cmd == CMD_DWR) {
            size_t outlen; uint8_t *resp = build_dwa(hbh, e2e, &outlen);
            if (resp) { write(fd, resp, outlen); free(resp); }
            if (body) free(body);
            continue;
        } else if (cmd == CMD_DPR) {
            size_t outlen; uint8_t *resp = build_dpa(hbh, e2e, &outlen);
            if (resp) { write(fd, resp, outlen); free(resp); }
            if (body) free(body);
            break; /* close after DPA */
        } else if (cmd == CMD_CC) {
            req_ctx_t ctx; memset(&ctx,0,sizeof(ctx));
            if (body && body_len) parse_ccr_body(body, body_len, &ctx);
            if (verbose) {
                fprintf(stderr, "[CCR parsed] session=%s has_sub=%d sub=%s req_total=%" PRIu64 " req_type=%u req_num=%u\n",
                        ctx.has_session?ctx.session_id:"(none)", ctx.has_sub, ctx.has_sub?ctx.sub_data:"-", ctx.requested_total_octets, ctx.cc_request_type, ctx.cc_request_number);
            }
            size_t outlen; uint8_t *cca = build_cca(&ctx, appid, hbh, e2e, &outlen);
            if (cca) { write(fd, cca, outlen); free(cca); }
            if (body) free(body);
            if (ctx.cc_request_type == 3) { if (verbose) fprintf(stderr,"Termination CCR — closing conn\n"); break; }
            continue;
        } else {
            if (verbose) fprintf(stderr, "Unknown command %u — ignoring\n", cmd);
            if (body) free(body);
            continue;
        }
    }
    close(fd);
    if (verbose) fprintf(stderr, "[*] connection closed fd=%d\n", fd);
    return NULL;
}

/* Simple command line parser */
static void usage(const char *p) {
    fprintf(stderr, "Usage: %s [-p port] [-H origin-host] [-R origin-realm] [-r top_result_code] [-m mscc_result_code] [-g max_grant_bytes] [-d default_grant_bytes] [-v]\n", p);
}
int main(int argc, char **argv) {
    int opt; int port = DEFAULT_PORT;
    while ((opt = getopt(argc, argv, "p:H:R:r:m:g:d:v")) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'H': strncpy(origin_host, optarg, sizeof(origin_host)-1); break;
            case 'R': strncpy(origin_realm, optarg, sizeof(origin_realm)-1); break;
            case 'r': top_result_code = (uint32_t)atoi(optarg); break;
            case 'm': mscc_result_code = (uint32_t)atoi(optarg); break;
            case 'g': max_grant_bytes = strtoull(optarg, NULL, 10); break;
            case 'd': default_grant_bytes = strtoull(optarg, NULL, 10); break;
            case 'v': verbose = 1; break;
            default: usage(argv[0]); return 1;
        }
    }
    if (verbose) {
        fprintf(stderr, "Starting OCS dynamic builder on port %d\n", port);
        fprintf(stderr, "origin-host=%s origin-realm=%s top-result=%u mscc-result=%u max-grant=%" PRIu64 " default-grant=%" PRIu64 "\n",
                origin_host, origin_realm, top_result_code, mscc_result_code, max_grant_bytes, default_grant_bytes);
    }

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int on = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = INADDR_ANY; sa.sin_port = htons(port);
    if (bind(srv, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); close(srv); return 1; }
    if (listen(srv, 16) < 0) { perror("listen"); close(srv); return 1; }
    fprintf(stderr, "OCS dynamic builder listening on 0.0.0.0:%d\n", port);
    while (1) {
        struct sockaddr_in ca; socklen_t cal = sizeof(ca);
        int fd = accept(srv, (struct sockaddr*)&ca, &cal);
        if (fd < 0) { perror("accept"); continue; }
        pthread_t th; pthread_create(&th, NULL, conn_handler, (void*)(intptr_t)fd); pthread_detach(th);
    }
    close(srv);
    return 0;
}

