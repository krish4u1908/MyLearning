#define DIAM_BUILD_RSP_HDR_FROM_REQ(rsp, req)               \
{                                                           \
    memcpy((rsp), (req), DIAMETER_HDR_SIZE);                \
    (rsp)[4] &= ~(DIAM_HDR_FLAG_REQUEST);                   \
}
uint64_t htonll(uint64_t value) {
    int num = 42;
    if (*(char *)&num == 42) {
        uint32_t high_part = htonl((uint32_t)(value >> 32));
        uint32_t low_part = htonl((uint32_t)(value & 0xFFFFFFFFLL));
        return (((uint64_t)low_part) << 32) | high_part;
    } else {
        return value;
    }
}
#define DIAM_BUILD_MSG_HDR(buff, fl, cc, a_id, hhid, eeid)  \
{                                                           \
    U8                  *ptr = (buff);                      \
    /* Set the version */                                   \
    DIAM_SET_U8((ptr), 0x01);                                \
    /* Set the Length */                                    \
    DIAM_SET_U24((ptr), 0x00);                               \
    /* Set the flags */                                     \
    DIAM_SET_U8((ptr), (fl));                                \
    /* Set the message command-code */                      \
    DIAM_SET_U24((ptr), (cc));                               \
    /* Set the diameter application-id */                   \
    DIAM_SET_U32((ptr), (a_id));                             \
    /* Set the hop-by-hop id */                             \
    DIAM_SET_U32((ptr), (hhid));                             \
    /* Set the end-to-end id */                             \
    DIAM_SET_U32((ptr), (eeid));                             \
}

#define DIAM_FIND_MIN_OF_TWO_VALS(a,b)                      \
(                                                           \
    (a) < (b) ? (a) : (b)                                   \
)

#define DIAM_FIND_MAX_OF_TWO_VALS(a,b)                      \
(                                                           \
    (a) > (b) ? (a) : (b)                                   \
)

#define DIAM_FIND_MIN_OF_THREE_VALS(a,b,c)                  \
(                                                           \
    (a) < (b) ? ((a) < (c) ? (a) : (c)) :                   \
    ((b) < (c) ? (b) : (c))                                 \
)

#define DIAM_FIND_MAX_OF_THREE_VALS(a,b,c)                  \
(                                                           \
    (a) > (b) ? ((a) > (c) ? (a) : (c)) :                   \
    ((b) > (c) ? (b) : (c))                                 \
)

#define pntoh24(p)  ((U32)*((const U8 *)(p)+0)<<16  |   \
                     (U32)*((const U8 *)(p)+1)<<8   |   \
                     (U32)*((const U8 *)(p)+2)<<0)

#define pntohs(p)  ((U16)                               \
                   ((U16)*((const U8 *)(p)+0)<<8    |   \
                   (U16)*((const U8 *)(p)+1)<<0))

#define pntohl(p)  ((U32)*((const U8 *)(p)+0)<<24   |   \
                   (U32)*((const U8 *)(p)+1)<<16    |   \
                   (U32)*((const U8 *)(p)+2)<<8     |   \
                   (U32)*((const U8 *)(p)+3)<<0)

#define pntoh64(p)  ((U64)*((const U8 *)(p)+0)<<56  |   \
                     (U64)*((const U8 *)(p)+1)<<48  |   \
                     (U64)*((const U8 *)(p)+2)<<40  |   \
                     (U64)*((const U8 *)(p)+3)<<32  |   \
                     (U64)*((const U8 *)(p)+4)<<24  |   \
                     (U64)*((const U8 *)(p)+5)<<16  |   \
                     (U64)*((const U8 *)(p)+6)<<8   |   \
                     (U64)*((const U8 *)(p)+7)<<0)

#define DIAM_SET_U64(p_buf, value)                      \
{                                                       \
    (p_buf)[0] = (U8)((U64)(value) >> 56);              \
    (p_buf)[1] = (U8)((U64)(value) >> 48);              \
    (p_buf)[2] = (U8)((U64)(value) >> 40);              \
    (p_buf)[3] = (U8)((U64)(value) >> 32);              \
    (p_buf)[4] = (U8)((U64)(value) >> 24);              \
    (p_buf)[5] = (U8)((U64)(value) >> 16);              \
    (p_buf)[6] = (U8)((U64)(value) >> 8);               \
    (p_buf)[7] = (U8)((U64)(value));                    \
    (p_buf) += 8;                                       \
}

#define DIAM_SET_U64_ARR(p_buf, value)                  \
{                                                       \
    (p_buf)[0] = (U8)((U64)(value) >> 56);              \
    (p_buf)[1] = (U8)((U64)(value) >> 48);              \
    (p_buf)[2] = (U8)((U64)(value) >> 40);              \
    (p_buf)[3] = (U8)((U64)(value) >> 32);              \
    (p_buf)[4] = (U8)((U64)(value) >> 24);              \
    (p_buf)[5] = (U8)((U64)(value) >> 16);              \
    (p_buf)[6] = (U8)((U64)(value) >> 8);               \
    (p_buf)[7] = (U8)((U64)(value));                    \
}

#define DIAM_SET_U32(p_buf, value)                      \
{                                                       \
    (p_buf)[0] = (U8)((U32)(value) >> 24);              \
    (p_buf)[1] = (U8)((U32)(value) >> 16);              \
    (p_buf)[2] = (U8)((U32)(value) >> 8);               \
    (p_buf)[3] = (U8)((U32)(value));                    \
    (p_buf) += 4;                                       \
}

#define DIAM_SET_U32_ARR(p_buf, value)                  \
{                                                       \
    (p_buf)[0] = (U8)((U32)(value) >> 24);              \
    (p_buf)[1] = (U8)((U32)(value) >> 16);              \
    (p_buf)[2] = (U8)((U32)(value) >> 8);               \
    (p_buf)[3] = (U8)((U32)(value));                    \
}

#define DIAM_SET_U24(p_buf, value)                      \
{                                                       \
    (p_buf)[0] = (U8)((U32)(value) >> 16);              \
    (p_buf)[1] = (U8)((U32)(value) >> 8);               \
    (p_buf)[2] = (U8)((U32)(value));                    \
    (p_buf) += 3;                                       \
}

#define DIAM_SET_U16(p_buf, value)                      \
{                                                       \
    (p_buf)[0]= (U8) ((value) >> 8);                    \
    (p_buf)[1]= (U8) (value);                           \
    (p_buf) += 2;                                       \
}

#define DIAM_SET_U16_ARR(p_buf, value)                  \
{                                                       \
    (p_buf)[0]= (U8) ((value) >> 8);                    \
    (p_buf)[1]= (U8) (value);                           \
}

#define DIAM_SET_U8(p_buf, value)                       \
{                                                       \
    (p_buf)[0] = (U8)(value);                           \
    (p_buf) += 1;                                       \
}

#define DIAM_SET_U8_WITH_MASK(p_buf, value, mask)       \
{                                                       \
    (p_buf)[0] = (U8)((value) & (mask));                \
    (p_buf) += 1;                                       \
}

#define DIAM_SET_NBYTES(p_buf, p_array, length)         \
{                                                       \
    memcpy((p_buf), (p_array), (length));               \
    (p_buf) += (length);                                \
}

#define DIAM_GET_U64(p_buf, value)                      \
{                                                       \
    (value) = (U64)(p_buf)[7]          |                \
              ((U64)(p_buf)[6] << 8)   |                \
              ((U64)(p_buf)[5] <<16)   |                \
              ((U64)(p_buf)[4] << 24)  |                \
              ((U64)(p_buf)[3] << 32)  |                \
              ((U64)(p_buf)[2] << 40)  |                \
              ((U64)(p_buf)[1] << 48)  |                \
              ((U64)(p_buf)[0] << 56);                  \
}

#define DIAM_GET_U32(p_buf, value)                      \
{                                                       \
    (value) = (U32)(p_buf)[3]          |                \
              ((U32)(p_buf)[2] << 8)   |                \
              ((U32)(p_buf)[1] <<16)   |                \
              ((U32)(p_buf)[0] << 24);                  \
}

#define DIAM_GET_U24(p_buf, value)                      \
{                                                       \
    (value) = (U32)(p_buf)[2]          |                \
              ((U32)(p_buf)[1] << 8)   |                \
              ((U32)(p_buf)[0] <<16);                   \
}

#define DIAM_GET_U16(p_buf, value)                      \
{                                                       \
    (value) = (U16)(p_buf)[1]          |                \
              (U16)((p_buf)[0] << 8);                   \
}

#define DIAM_GET_U8(p_buf, value)                       \
{                                                       \
    (value) = (p_buf)[0];                               \
}

#define DIAM_GET_U8_WITH_MASK(p_buf, value, mask)       \
{                                                       \
    (value) = (p_buf)[0] & (mask);                      \
    (p_buf) += 1;                                       \
}

#define DIAM_GET_NBYTES(p_buf, p_array, length)         \
{                                                       \
    memcpy((p_array), (p_buf), (length));               \
    (p_buf) += (length);                                \
}

#define STRCPY(dest,src)         strcpy((char *)(dest), (const char *)(src))
#define STRNCPY(dest,src,n)      strncpy((char *)(dest), (const char *)(src), (size_t)(n))
#define STRLEN(s)                strlen((const char *)(s))

#define DIAM_SET_STR_TO_LOWER(_str, _len) do{\
    U16 _idx = 0;\
    for(; _idx < (_len); _idx++) {\
        (_str)[_idx] = tolower((_str)[_idx]); \
    }\
}while(0);

#define DIAM_REMOVE_CRLF_COMMENT_FROM_STR(p_val, rec_len) do {\
    U16  _indx = 0; \
    for(_indx = 0; _indx < (rec_len); _indx++) {\
        if(((p_val)[_indx] == '\n') || ((p_val)[_indx] == '\r') || ((p_val)[_indx] == '#')) {\
            memset(&((p_val)[_indx]), '\0', (1+STRLEN(&((p_val)[_indx])))); \
            break;\
        }\
    }\
    (rec_len) = STRLEN((p_val)); \
}while(0);

#define DIAM_REMOVE_WHITE_SPACE_FROM_STR(p_val, rec_len) do{\
    U16  _indx = 0, _lindx = 0, _llen = 0; \
    for(;((p_val)[_indx] != '\0') && ((p_val)[_indx] != '\n') && (_indx < (rec_len)); _indx++) {\
        if(((p_val)[_indx] == ' ') || ((p_val)[_indx] == '\t')) {\
            _lindx = _indx; \
            while(((p_val)[_lindx] == ' ') || ((p_val)[_lindx] == '\t')) {\
                _lindx++; \
            }\
            if(((p_val)[_lindx] == '\0') || ((p_val)[_lindx] == '\n')) {\
                memset(&((p_val)[_indx]), '\0', (_lindx-_indx)); \
                break; \
            } else { \
                _llen = STRLEN(&((p_val)[_lindx])); \
                memmove(&((p_val)[_indx]), &((p_val)[_lindx]), _llen); \
                memset(&((p_val)[_indx + _llen]), '\0', (_lindx-_indx)); \
            }\
            (rec_len) = STRLEN((p_val)); \
        }\
    }\
}while(0);

