#ifndef RADIUS_MOD_H
#define RADIUS_MOD_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Module type: choose a free low-byte type (example: 0x06) */
#ifndef LTE_PGW_RADIUS_MODULE
#define LTE_PGW_RADIUS_MODULE   0x06
#endif

/* QMODULE helpers (usually already present in your tree) */
#ifndef PGW_MODULE_ID
#define PGW_MODULE_ID(cei, type)   ( (uint16_t)((((uint16_t)(cei)) << 8) | ((uint16_t)(type) & 0xFF)) )
#endif

/* RADIUS codes (subset) */
#define RADIUS_ACCESS_REQUEST        1
#define RADIUS_ACCESS_ACCEPT         2
#define RADIUS_ACCESS_REJECT         3
#define RADIUS_ACCOUNTING_REQUEST    4
#define RADIUS_ACCOUNTING_RESPONSE   5
#define RADIUS_CODE_STATUS_SERVER   12

/* Accounting Status-Type */
#define RAD_ACCT_STATUS_START        1
#define RAD_ACCT_STATUS_STOP         2
#define RAD_ACCT_STATUS_INTERIM      3

/* Events posted to RADIUS module entry() */
typedef enum {
    EV_RAD_AUTH_REQ = 0xE100,
    EV_RAD_ACCT_START,
    EV_RAD_ACCT_INTERIM,
    EV_RAD_ACCT_STOP,
    EV_RAD_RESPONSE,         /* internal: recv_cb → entry */
    EV_RAD_TIMEOUT,          /* internal: timer fired */
    EV_RAD_SERVER_FAILOVER   /* internal */
} radius_event_e;

/* Minimal request payloads sent to radius_entry() */
typedef struct {
    /* mandatory identifiers for correlation */
    uint64_t    sess_id;            /* your session key */
    uint32_t    teid;               /* optional */
    char        imsi[32];           /* optional */

    /* framed IP if available */
    uint32_t    ue_ipv4;            /* in network order; 0 if not set */

    /* optional attributes you want to include */
    const char *user_name;          /* may be IMSI/MSISDN */
    const char *calling_station_id; /* MSISDN/IMSI */
    const char *nas_ip;             /* printable NAS IP */
} rad_auth_req_t;

typedef struct {
    uint64_t    sess_id;
    uint32_t    teid;

    /* acct core fields */
    uint8_t     status_type;        /* START/INTERIM/STOP */
    uint64_t    in_octets;          /* 64-bit */
    uint64_t    out_octets;
    uint32_t    session_time;       /* seconds */
    uint32_t    cause;              /* vendor-specific if needed */

    uint32_t    ue_ipv4;            /* network order, optional */
    const char *nas_ip;             /* printable NAS IP */
} rad_acct_req_t;

/* Response up to caller (post back to M-Module typically) */
typedef struct {
    uint64_t    sess_id;
    uint8_t     code;               /* ACCEPT / REJECT / ACCT-RESP */
    uint8_t     identifier;         /* matched identifier */
    int         ok;                 /* 1=valid auth & verified; 0=bad */
    int         errno_like;         /* reason code on failure */
} rad_result_t;

/* Per-CEI configuration (set via M2 config or static) */
typedef struct {
    /* Server list (primary + backups) */
    struct {
        struct sockaddr_storage   auth_addr;  /* 1812 */
        socklen_t                 auth_len;
        struct sockaddr_storage   acct_addr;  /* 1813 */
        socklen_t                 acct_len;
    } servers[4]; /* primary + up to 3 backups */

    int       servers_count;
    char      shared_secret[128];

    /* Retry/backoff */
    uint8_t   max_retries;      /* e.g., 3 */
    uint32_t  t1_ms;            /* e.g., 1000 */
    float     backoff;          /* e.g., 2.0 */

    /* Interim interval (seconds) if you schedule in module */
    uint32_t  interim_s;

    /* Local bind (optional) */
    struct sockaddr_storage local_bind;
    socklen_t               local_len;
} radius_cfg_t;

/* Integration surface */
void radius_set_cfg(uint8_t cei, const radius_cfg_t *cfg);

/* Registration helper: call from your gtpd_register_modules() for worker CEIs */
int  radius_register_on_cei(uint8_t cei);

/* Utility to post from other modules on same worker CEI */
static inline uint16_t radius_qmodule(uint8_t cei) {
    return PGW_MODULE_ID(cei, LTE_PGW_RADIUS_MODULE);
}

#ifdef __cplusplus
}
#endif
#endif /* RADIUS_MOD_H */
