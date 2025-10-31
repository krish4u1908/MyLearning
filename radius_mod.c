#include "radius_mod.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

/* ---- CSPL/QMODULE integration (adapt includes to your tree) ---- */
#include "qv.h"          /* qvPost, qvSelf, timers */
#include "nmn_ipc.h"     /* gtpd_recv_register */
#include "lte_log.h"     /* LTE_TRACE/LTE_LOG */

/* ---- Module ID helpers (low-byte type is 0x06) ---- */
#ifndef PGW_MODULE_ID
#define PGW_MODULE_ID(cei, type)   ( (uint16_t)((((uint16_t)(cei)) << 8) | ((uint16_t)(type) & 0xFF)) )
#endif
#ifndef PGW_MODULE_CEI
#define PGW_MODULE_CEI(qmod)       ( (uint8_t)((qmod) >> 8) )
#endif

/* ---- Local constants ---- */
#define RADIUS_HDR_LEN   20
#define RADIUS_MAX_PKT   4096
#define RADIUS_MAX_OUT   1024

/* ---- Simple crypto hooks (plug your MD5/HMAC here) ---- */
static void md5_sum(const uint8_t *data, size_t len, uint8_t out16[16]);
static void hmac_md5(const uint8_t *key, size_t klen,
                     const uint8_t *data, size_t dlen, uint8_t out16[16]);

/* ---- Per-CEI context ---- */
typedef struct {
    int              fd_v4;      /* UDP for both auth/acct or split later */
    int              fd_v6;
    uint8_t          next_id;    /* 0..255 per CEI */
    radius_cfg_t     cfg;

    /* simplistic pending map; replace with rhashtab if you have one */
    struct pending {
        uint8_t     in_use;
        uint8_t     identifier;
        uint8_t     is_acct;     /* 0=auth,1=acct */
        uint8_t     retries;
        uint32_t    timer_id;    /* QV timer handle */
        uint64_t    sess_id;
        struct sockaddr_storage dst;
        socklen_t   dst_len;
        uint8_t     request[RADIUS_MAX_OUT];
        size_t      req_len;
    } pend[256];

    /* metrics (atomic if you prefer) */
    uint64_t auth_sent, auth_ok, auth_fail;
    uint64_t acct_sent, acct_ok, acct_fail;
    uint64_t retries_cnt, failovers, drops, rx_bytes, tx_bytes;
} radius_cei_ctx_t;

static radius_cei_ctx_t g_ctx[256]; /* supports up to 256 CEIs */

/* ---- Forward decl ---- */
static void radius_entry(uint32_t ev, void *msg);
static void radius_timer_cb(uint32_t tid);
static void radius_recv_cb(int fd, void *u);

/* ---- Helpers ---- */
static inline uint64_t nsec_now(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec*1000000000ull + ts.tv_nsec;
}
static int set_nonblock(int fd){ int f=fcntl(fd, F_GETFL,0); return fcntl(fd, F_SETFL, f|O_NONBLOCK); }

/* ---- Packet encode minimal (AVPs very limited demo) ---- */
static size_t rad_put_avp(uint8_t *p, uint8_t type, const void *val, uint8_t len){
    p[0]=type; p[1]=len+2; memcpy(p+2,val,len); return (size_t)(len+2);
}
static size_t rad_put_avp_string(uint8_t *p, uint8_t type, const char *s){
    size_t L = s? strlen(s):0; if (L>253) L=253; return rad_put_avp(p,type,s,(uint8_t)L);
}
static size_t rad_put_avp_u32(uint8_t *p, uint8_t type, uint32_t v_net){
    uint32_t v = v_net; return rad_put_avp(p,type,&v,4);
}

/* RFC 2865 header:
   0: Code(1) 1: Identifier(1) 2-3: Length(2) 4-19: Authenticator(16) */
static size_t rad_build_request(uint8_t code, uint8_t identifier,
                                const char *secret,
                                uint8_t *out, size_t out_cap,
                                size_t (*fill_avps)(uint8_t *attr))
{
    if (out_cap < RADIUS_HDR_LEN) return 0;
    memset(out,0,out_cap);
    out[0]=code;
    out[1]=identifier;
    /* length filled later */
    /* random request authenticator */
    for (int i=4;i<20;i++) out[i]=(uint8_t)rand();

    uint8_t *attr = out + RADIUS_HDR_LEN;
    size_t   attr_len = fill_avps(attr);

    uint16_t total_len = (uint16_t)(RADIUS_HDR_LEN + attr_len);
    out[2] = (uint8_t)(total_len >> 8);
    out[3] = (uint8_t)(total_len & 0xFF);

    /* For Access-Request, Request Authenticator is random (already set) */
    /* For Accounting-Request, Authenticator = MD5(Code+Id+Len+RA(16=0)+AVPs+Secret) */
    if (code == RADIUS_ACCOUNTING_REQUEST) {
        uint8_t tmp[RADIUS_MAX_OUT];
        if (total_len > sizeof(tmp)) return 0;
        memcpy(tmp, out, total_len);
        memset(tmp+4, 0, 16);
        size_t sec_len = strlen(secret);
        if (total_len + sec_len > sizeof(tmp)) return 0;
        memcpy(tmp+total_len, secret, sec_len);
        uint8_t md[16]; md5_sum(tmp, total_len+sec_len, md);
        memcpy(out+4, md, 16);
    }
    return total_len;
}

/* Verify response authenticator (simplified) */
static int rad_verify_response(const uint8_t *req, size_t req_len,
                               const uint8_t *resp, size_t resp_len,
                               const char *secret)
{
    if (resp_len < RADIUS_HDR_LEN) return 0;
    uint8_t code = resp[0], id = resp[1];
    /* Response Authenticator = MD5(Code+Id+Len+RequestAuth+AVPs+Secret) */
    uint8_t tmp[RADIUS_MAX_PKT];
    if (resp_len > sizeof(tmp)) return 0;
    memcpy(tmp, resp, resp_len);
    /* substitute RequestAuth from request */
    memcpy(tmp+4, req+4, 16);
    size_t sec_len = strlen(secret);
    memcpy(tmp+resp_len, secret, sec_len);
    uint8_t md[16]; md5_sum(tmp, resp_len+sec_len, md);
    return (memcmp(md, resp+4, 16) == 0) ? 1 : 0;
}

/* ---- Public: set config ---- */
void radius_set_cfg(uint8_t cei, const radius_cfg_t *cfg){
    if (!cfg) return;
    g_ctx[cei].cfg = *cfg;
}

/* ---- Registration on a CEI (called for workers only) ---- */
int radius_register_on_cei(uint8_t cei){
    radius_cei_ctx_t *cx = &g_ctx[cei];

    /* Create a single UDP socket (v4) for both auth/acct for demo */
    cx->fd_v4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (cx->fd_v4 < 0) return -1;
    set_nonblock(cx->fd_v4);

    /* Optional local bind if provided */
    if (cx->cfg.local_len && cx->cfg.local_bind.ss_family == AF_INET) {
        if (bind(cx->fd_v4, (struct sockaddr*)&cx->cfg.local_bind, cx->cfg.local_len) < 0) {
            LTE_LOG("RADIUS: bind v4 failed: %d", errno);
        }
    }

    /* Register recv callback with this CEI reactor */
    gtpd_recv_register(/*ctx*/NULL /* your module ctx if required */,
                       cx->fd_v4, radius_recv_cb, (void*)(uintptr_t)cei);

    /* Register module with QV (pseudo – adapt to your manifest system) */
    /* qvRegisterEx(cei_table[cei].driver, ..., radius_entry, radius_timer_cb, ...); */

    LTE_LOG("RADIUS: registered on CEI=%u fd_v4=%d", cei, cx->fd_v4);
    return 0;
}

/* ---- Send helpers ---- */
static int radius_send_to(radius_cei_ctx_t *cx, const struct sockaddr *dst, socklen_t dlen,
                          uint8_t *pkt, size_t plen)
{
    ssize_t n = sendto(cx->fd_v4, pkt, plen, 0, dst, dlen);
    if (n > 0) { cx->tx_bytes += (uint64_t)n; return 0; }
    return -1;
}

/* ---- Pending map helpers ---- */
static struct pending *pend_alloc(radius_cei_ctx_t *cx, uint8_t *out_id){
    for (int i=0;i<256;i++){
        if (!cx->pend[i].in_use){
            cx->pend[i].in_use = 1;
            cx->pend[i].identifier = cx->next_id++;
            *out_id = cx->pend[i].identifier;
            return &cx->pend[i];
        }
    }
    return NULL;
}
static struct pending *pend_get(radius_cei_ctx_t *cx, uint8_t id){
    for (int i=0;i<256;i++){
        if (cx->pend[i].in_use && cx->pend[i].identifier == id) return &cx->pend[i];
    }
    return NULL;
}
static void pend_free(struct pending *p){ memset(p,0,sizeof(*p)); }

/* ---- Build AVPs for Auth ---- */
static size_t fill_auth_avps(uint8_t *attr, const rad_auth_req_t *req){
    size_t off=0;
    if (req->user_name)           off += rad_put_avp_string(attr+off, 1 /*User-Name*/, req->user_name);
    if (req->calling_station_id)  off += rad_put_avp_string(attr+off, 31/*Calling-Station-Id*/, req->calling_station_id);
    if (req->nas_ip)              off += rad_put_avp_string(attr+off, 4 /*NAS-IP-Address (string form acceptable for demo)*/, req->nas_ip);
    if (req->ue_ipv4)             off += rad_put_avp_u32(attr+off, 8 /*Framed-IP-Address*/, req->ue_ipv4);
    /* Add Service-Type/NAS-Port-Type as needed */
    return off;
}

/* ---- Build AVPs for Accounting ---- */
static size_t fill_acct_avps(uint8_t *attr, const rad_acct_req_t *req){
    size_t off=0;
    uint32_t v;

    /* Acct-Status-Type */
    v = htonl((uint32_t)req->status_type);
    off += rad_put_avp(attr+off, 40 /*Acct-Status-Type*/, &v, 4);

    /* Session-Id (string) – for demo use sess_id as hex */
    char sid[32]; snprintf(sid,sizeof(sid),"%016llx",(unsigned long long)req->sess_id);
    off += rad_put_avp_string(attr+off, 44 /*Acct-Session-Id*/, sid);

    /* Octets 64 (vendor/int?) – for demo include standard 32-bit if needed */
    uint32_t in32  = htonl((uint32_t)(req->in_octets  & 0xFFFFFFFFu));
    uint32_t out32 = htonl((uint32_t)(req->out_octets & 0xFFFFFFFFu));
    off += rad_put_avp(attr+off, 42 /*Acct-Input-Octets*/,  &in32,  4);
    off += rad_put_avp(attr+off, 43 /*Acct-Output-Octets*/, &out32, 4);

    if (req->ue_ipv4) off += rad_put_avp_u32(attr+off, 8 /*Framed-IP-Address*/, req->ue_ipv4);
    if (req->nas_ip)  off += rad_put_avp_string(attr+off, 4 /*NAS-IP-Address (string for demo)*/, req->nas_ip);

    v = htonl(req->session_time);
    off += rad_put_avp(attr+off, 46 /*Acct-Session-Time*/, &v, 4);

    return off;
}

/* ---- Entry() – handles posts ---- */
static void radius_entry(uint32_t ev, void *msg){
    uint8_t cei = qvSelf();
    radius_cei_ctx_t *cx = &g_ctx[cei];

    if (ev == EV_RAD_AUTH_REQ) {
        rad_auth_req_t *rq = (rad_auth_req_t*)msg;

        uint8_t id; struct pending *p = pend_alloc(cx, &id);
        if (!p) return;

        p->sess_id = rq->sess_id; p->is_acct=0; p->retries=0;
        /* choose server 0 (primary) for now */
        const struct sockaddr *dst = (const struct sockaddr*)&cx->cfg.servers[0].auth_addr;
        socklen_t dlen = cx->cfg.servers[0].auth_len;
        p->dst = *(const struct sockaddr_storage*)dst; p->dst_len = dlen;

        /* build packet */
        p->req_len = rad_build_request(RADIUS_ACCESS_REQUEST, id, cx->cfg.shared_secret,
                                       p->request, sizeof(p->request),
            /* fill avps */ (size_t(*)(uint8_t*)) (^(uint8_t *attr){ return fill_auth_avps(attr, rq); }) /* GNU ext not portable */
        );
        /* Replace the lambda with static wrapper to be portable */
        /* For portability, we rebuild here: */
        p->req_len = rad_build_request(RADIUS_ACCESS_REQUEST, id, cx->cfg.shared_secret,
                                       p->request, sizeof(p->request),
                                       NULL);
        /* fill AVPs manually */
        size_t avp_len = fill_auth_avps(p->request + RADIUS_HDR_LEN, rq);
        uint16_t total = (uint16_t)(RADIUS_HDR_LEN + avp_len);
        p->request[2] = (uint8_t)(total >> 8);
        p->request[3] = (uint8_t)(total & 0xFF);

        (void)radius_send_to(cx, (struct sockaddr*)&p->dst, p->dst_len, p->request, total);
        cx->auth_sent++;

        /* start timer T1 */
        p->timer_id = qvStartTimer(/*module*/PGW_MODULE_ID(cei, LTE_PGW_RADIUS_MODULE),
                                   EV_RAD_TIMEOUT, id, cx->cfg.t1_ms);
        return;
    }

    if (ev == EV_RAD_ACCT_START || ev == EV_RAD_ACCT_INTERIM || ev == EV_RAD_ACCT_STOP) {
        rad_acct_req_t *rq = (rad_acct_req_t*)msg;

        uint8_t id; struct pending *p = pend_alloc(cx, &id);
        if (!p) return;

        p->sess_id = rq->sess_id; p->is_acct=1; p->retries=0;

        const struct sockaddr *dst = (const struct sockaddr*)&cx->cfg.servers[0].acct_addr;
        socklen_t dlen = cx->cfg.servers[0].acct_len;
        p->dst = *(const struct sockaddr_storage*)dst; p->dst_len = dlen;

        /* Build accounting request (with MD5 authenticator) */
        p->req_len = rad_build_request(RADIUS_ACCOUNTING_REQUEST, id, cx->cfg.shared_secret,
                                       p->request, sizeof(p->request),
                                       NULL);
        size_t avp_len = fill_acct_avps(p->request + RADIUS_HDR_LEN, rq);
        uint16_t total = (uint16_t)(RADIUS_HDR_LEN + avp_len);
        p->request[2] = (uint8_t)(total >> 8);
        p->request[3] = (uint8_t)(total & 0xFF);

        /* recompute authenticator for accounting (since auth depends on whole PDU) */
        {
            uint8_t tmp[RADIUS_MAX_OUT];
            memcpy(tmp, p->request, total);
            memset(tmp+4, 0, 16);
            size_t sec_len = strlen(cx->cfg.shared_secret);
            memcpy(tmp+total, cx->cfg.shared_secret, sec_len);
            uint8_t md[16]; md5_sum(tmp, total+sec_len, md);
            memcpy(p->request+4, md, 16);
        }

        (void)radius_send_to(cx, (struct sockaddr*)&p->dst, p->dst_len, p->request, total);
        cx->acct_sent++;

        p->timer_id = qvStartTimer(PGW_MODULE_ID(cei, LTE_PGW_RADIUS_MODULE),
                                   EV_RAD_TIMEOUT, id, cx->cfg.t1_ms);
        return;
    }

    if (ev == EV_RAD_RESPONSE) {
        /* msg is raw response pointer (wrap appropriately in your tree) */
        /* Here we assume msg points to a buffer: [id(1)][len(2)][ptr to raw resp] – adapt as needed */
        /* For brevity, skip this and handle in recv_cb -> directly verify and post result to M */
        return;
    }

    if (ev == EV_RAD_TIMEOUT) {
        uint8_t id = (uint8_t)(uintptr_t)msg;
        struct pending *p = pend_get(cx, id);
        if (!p) return;

        if (p->retries++ < cx->cfg.max_retries) {
            uint32_t delay = (uint32_t)(cx->cfg.t1_ms * (cx->cfg.backoff > 0 ? cx->cfg.backoff : 1.0f) * p->retries);
            (void)radius_send_to(cx, (struct sockaddr*)&p->dst, p->dst_len, p->request, p->req_len);
            cx->retries_cnt++;
            p->timer_id = qvStartTimer(PGW_MODULE_ID(cei, LTE_PGW_RADIUS_MODULE),
                                       EV_RAD_TIMEOUT, id, delay);
        } else {
            /* give up; inform M-Module on same CEI */
            rad_result_t *res = calloc(1, sizeof(*res));
            res->sess_id = p->sess_id; res->identifier = id; res->ok = 0; res->errno_like = ETIMEDOUT;
            uint16_t m_id = PGW_MODULE_ID(cei, /*LTE_PGW_M_MODULE*/ 0x02);
            qvPost(PGW_MODULE_ID(cei, LTE_PGW_RADIUS_MODULE), m_id, /*EV_M_AUTH_RESULT*/ 0xE200, res, sizeof(*res));
            pend_free(p);
        }
        return;
    }
}

/* ---- recv_cb: parse, verify, and post result ---- */
static void radius_recv_cb(int fd, void *u){
    uint8_t cei = (uint8_t)(uintptr_t)u;
    radius_cei_ctx_t *cx = &g_ctx[cei];
    uint8_t buf[RADIUS_MAX_PKT];
    struct sockaddr_storage peer; socklen_t plen=sizeof(peer);

    for(;;){
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&peer, &plen);
        if (n < 0) { if (errno==EAGAIN || errno==EWOULDBLOCK) break; return; }
        if (n < RADIUS_HDR_LEN) continue;

        cx->rx_bytes += (uint64_t)n;

        uint8_t code = buf[0], id = buf[1];
        struct pending *p = pend_get(cx, id);
        if (!p){ cx->drops++; continue; }

        /* Verify response authenticator */
        if (!rad_verify_response(p->request, p->req_len, buf, (size_t)n, cx->cfg.shared_secret)) {
            cx->drops++; continue;
        }

        /* Success: cancel timer & free pending */
        if (p->timer_id) qvStopTimer(p->timer_id);

        rad_result_t *res = calloc(1,sizeof(*res));
        res->sess_id = p->sess_id; res->identifier = id; res->ok = 1; res->code = code;

        /* Post back to M-Module on same CEI */
        uint16_t m_id = PGW_MODULE_ID(cei, /*LTE_PGW_M_MODULE*/ 0x02);
        qvPost(PGW_MODULE_ID(cei, LTE_PGW_RADIUS_MODULE), m_id, /*EV_M_AUTH_RESULT*/ 0xE200, res, sizeof(*res));

        if (p->is_acct) cx->acct_ok++; else cx->auth_ok++;
        pend_free(p);
    }
}

/* ---- Timer trampoline for QV (adapt signature to your qv) ---- */
static void radius_timer_cb(uint32_t tid){
    /* If your QV hands back timer payload (id), call entry with EV_RAD_TIMEOUT */
    radius_entry(EV_RAD_TIMEOUT, (void*)(uintptr_t)tid);
}

/* ---- Crypto stubs (plug your platform's MD5/HMAC here) ---- */
#include <openssl/md5.h>
static void md5_sum(const uint8_t *data, size_t len, uint8_t out16[16]){
    MD5_CTX c; MD5_Init(&c); MD5_Update(&c, data, len); MD5_Final(out16, &c);
}
static void hmac_md5(const uint8_t *key, size_t klen,
                     const uint8_t *data, size_t dlen, uint8_t out16[16]){
    /* optional if you add Message-Authenticator(80) AVP */
    (void)key; (void)klen; (void)data; (void)dlen; memset(out16,0,16);
}
