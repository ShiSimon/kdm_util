#include <stdio.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>
//#include <utility>
#include <string>
#include <memory>
#include <time.h>

#include "tinyxml.h"
#include "kdm.hpp"
#include "base64.h"
#include "test_rsa.h"

#define ST_INFO __FILE__,__LINE__

static int HexToNum(char c);
static int ScanHexOctet( unsigned char octxt[], const char *str, int sz);

static int HexToNum(char c)
{
    switch(c)
    {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'A': return 10;
    case 'B': return 11;
    case 'C': return 12;
    case 'D': return 13;
    case 'E': return 14;
    case 'F': return 15;
    case 'a': return 10;
    case 'b': return 11;
    case 'c': return 12;
    case 'd': return 13;
    case 'e': return 14;
    case 'f': return 15;        
    default: return -1;
    }
}

static int ScanHexOctet( unsigned char octxt[], const char *str, int sz)
{
    int i = 0;
    int j = 0;
    for(i=0;i<sz && *str != 0;i++, str++)
    {
        int h = HexToNum(*str);
        if(h == -1) return 0;
        str++;
        i++;
        if(!(i<sz  && *str != 0)) break;
        int l = HexToNum(*str);
        if(l == -1) return 0;
        octxt[j++] = (unsigned char)((h<<4) | l);
    }
    if( i<sz)
    {
        return 0;
    }
    return 1;
}

int PrintUuid(char uuid_buf[45], const unsigned char uuid[16], int flag)
{
    const char *fmt = 0;
    if( flag & UUID_NO_PREFIX)
    {
        if( flag & UUID_NO_HYPHEN)
        {
            fmt = "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x";
        }
        else
        {
            fmt = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x";
        }
    }
    else
    {
        if( flag & UUID_NO_HYPHEN)
        {
            fmt = "urn:uuid:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x";
        }
        else
        {
            fmt = "urn:uuid:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x";            
        }
    }
    
    snprintf( uuid_buf, 45, fmt, 
              uuid[0],uuid[1],uuid[2],uuid[3],
              uuid[4],uuid[5],
              uuid[6],uuid[7],
              uuid[8],uuid[9],
              uuid[10],uuid[11],uuid[12],uuid[13],uuid[14],uuid[15]);
    return 0;
}

int ParseUuid(unsigned char uuid[16], const char *uuid_str)
{
    // urn:uuid:2d68a8b6-a0df-4242-a8dc-ffbfbe126c40
    const char *p = strstr( uuid_str, "urn:uuid:");
    if( p == 0)
    {
        return 0;
    }
    p += 9;                     // skip urn:uuid:
    if(!ScanHexOctet(uuid, p, 8)) return 0;
    p += 8;
    if(*p!='-') return 0;
    p++;

    if(!ScanHexOctet(uuid+4, p, 4)) return 0;
    p += 4;
    if(*p!='-') return 0;
    p++;

    if(!ScanHexOctet(uuid+6, p, 4)) return 0;
    p += 4;
    if(*p!='-') return 0;
    p++;


    if(!ScanHexOctet(uuid+8, p, 4)) return 0;
    p += 4;
    if(*p!='-') return 0;
    p++;    

    if(!ScanHexOctet(uuid+10, p, 12)) return 0;

    // print it;
#if 0
    fprintf( stderr, "ParseUuid:%s->", uuid_str);
    for( int i=0; i < 16; i++)
    {
        fprintf(stderr, "%02X", uuid[i]);
    }
    fprintf( stderr,"\n");
#endif    
    return 1;
}

int ParseUtc( unsigned long long *utc, const char *utc_str)
{
    // 2004-05-01T13:20:00-08:00
    int year, month, day, hour, min, sec, dist_hour, dist_min;
    if( 8 != sscanf( utc_str, "%d-%d-%dT%d:%d:%d%d:%d",
                     &year, &month, &day,
                     &hour, &min, &sec,
                     &dist_hour, &dist_min))
    {
        fprintf( stderr, "utc_str=\"%s\"\n", utc_str);
        return -1;
    }
    //fprintf( stderr, "%d %d %d %d %d %d %d %d\n", year, month, day, hour, min, sec, dist_hour, dist_min);
    struct tm tm_utc;
    if( year < 1900) return -1;
    if( month < 1 || month > 12) return -1;
    if( day < 1 || day > 31) return -1;
    if( hour < 0 || hour > 23) return -1;
    if( min < 0 || min > 59) return -1;
    if( sec < 0 || sec > 59) return -1;
    if( dist_hour < 0 || dist_hour > 23) return -1;
    if( dist_min < 0 || dist_min > 59) return -1;
    tm_utc.tm_year = year - 1900;
    tm_utc.tm_mon = month -1;
    tm_utc.tm_mday = day;
    tm_utc.tm_hour = hour;
    tm_utc.tm_min = min;
    tm_utc.tm_sec = sec;
    tm_utc.tm_isdst = 0;

    time_t time_utc = mktime(&tm_utc); // time_utc: the local time

    // TODO: set the time dist!!

    *utc = (unsigned long long)time_utc;
    return 0;
}

int Kdm::Open( const char *kdm_fn)
{
    int i = 0;
    int ret = 0;

    if( IsOpen())
    {
        return -ERR_KDM_OPENED;
    }
    
    std::auto_ptr<TiXmlDocument> kdm_doc(new TiXmlDocument(kdm_fn));
    if(!(kdm_doc->LoadFile()))
    {
        fprintf( stderr, "kdm_open: Load [%s] fail\n", kdm_fn);
        return -ERR_KDM_LOAD_XML;
    }
    TiXmlHandle xml_handle(kdm_doc.get());
    TiXmlElement * p_xml_kdm = NULL; // RequiredExtensions or KDMRequiredExtensions
    TiXmlElement *p_elem = NULL;
    TiXmlElement *p_key = NULL;
    bool use_etm = false;

    // MSG-uuid
    TiXmlText *p_txt =
        xml_handle.
        FirstChild("DCinemaSecurityMessage").
        FirstChild("AuthenticatedPublic").
        FirstChild("MessageId").
        FirstChild().Text();
    if( p_txt == 0)
    {
        p_txt = xml_handle.
            FirstChild("etm:DCinemaSecurityMessage").
            FirstChild("etm:AuthenticatedPublic").
            FirstChild("etm:MessageId").
            FirstChild().Text();
        //fprintf( stderr, "ERR:Kdm::Open: MessageId not found\n");
        if(p_txt == 0)
        {
            return -ERR_KDM_NO_MSG_UUID;
        }
        else
        {
            use_etm = true;
        }
    }
    if( !ParseUuid(msg_uuid_, p_txt->Value()))
    {
        fprintf( stderr, "ERR:Kdm::Open: \"%s\' not a msg-uuid\n", p_txt->Value());
        return -ERR_KDM_BAD_MSG_UUID;
    }

    //fprintf( stderr, "Kdm::Open msg uuid OK\n");  

    if(use_etm)
    {
        p_xml_kdm =  xml_handle.
            FirstChild("etm:DCinemaSecurityMessage").
            FirstChild("etm:AuthenticatedPublic").
            FirstChild("etm:RequiredExtensions").
            FirstChild("KDMRequiredExtensions").
            Element();
    }
    else
    {
        p_xml_kdm =  xml_handle.
            FirstChild("DCinemaSecurityMessage").
            FirstChild("AuthenticatedPublic").
            FirstChild("RequiredExtensions").
            FirstChild("KDMRequiredExtensions").
            Element();
    }
    if(p_xml_kdm == 0)
    {
        if(use_etm)
        {
            p_xml_kdm =  xml_handle.
                FirstChild("etm:DCinemaSecurityMessage").
                FirstChild("etm:AuthenticatedPublic").
                FirstChild("etm:RequiredExtensions").
                Element();
        }
        else
        {
            p_xml_kdm =  xml_handle.
                FirstChild("DCinemaSecurityMessage").
                FirstChild("AuthenticatedPublic").
                FirstChild("RequiredExtensions").
                Element();
        }
        if( p_xml_kdm == 0)
        {
            fprintf( stderr, "ERR:Kdm::Open: p_xml_kdm not found\n");
            return -ERR_KDM_NO_KDM_ELEMENT;
        }
    }  

    // CPL-uudi
    p_txt = p_xml_kdm->
        FirstChild("CompositionPlaylistId")->
        FirstChild()->
        ToText();
    if( p_txt == 0)
    {
        fprintf( stderr, "ERR:Kdm::Open: CPL uuid not found\n");
        return -ERR_KDM_NO_CPL_UUID;
    }
    if( !ParseUuid(cpl_uuid_, p_txt->Value()))
    {
        fprintf( stderr, "ERR:Kdm::Open: \"%s\" not a cpl-uuid\n", p_txt->Value());
        return -ERR_KDM_BAD_CPL_UUID;
    }

    //fprintf( stderr, "Kdm::Open cpl uuid OK\n");        
    

    // content title
    p_txt = p_xml_kdm->
        FirstChild("ContentTitleText")->
        FirstChild()->
        ToText();
    if( !p_txt)
    {
        fprintf( stderr, "ERR:Kdm::Open: content title not found\n");
        return -ERR_KDM_NO_CONTENT_TITLE;
    }
    try
    {
        content_title_ = p_txt->Value();
    }
    catch(...)
    {
        fprintf( stderr, "ERR:Kdm::Open: \"%s\" assign content title fail\n", p_txt->Value());
        return -ERR_KDM_ASSIGN_CONTENT_TITLE;
    }
    //fprintf( stderr, "Kdm::Open content title OK\n");

    // not valid after, not valid before
    p_txt = p_xml_kdm->
        FirstChild("ContentKeysNotValidBefore")->
        FirstChild()->
        ToText();
    if( p_txt == 0)
    {
        return -ERR_KDM_NO_NV_BEFORE;        
    }
    
    if( ParseUtc( &nv_before_, p_txt->Value()) < 0)
    {
        return -ERR_KDM_BAD_NV_BEFORE;
    }
        
    p_txt = p_xml_kdm->
        FirstChild("ContentKeysNotValidAfter")->
        FirstChild()->
        ToText();
    if( p_txt == 0)
    {
        return -ERR_KDM_NO_NV_AFTER;        
    }
    
    if( ParseUtc( &nv_after_, p_txt->Value()) < 0)
    {
        return -ERR_KDM_BAD_NV_AFTER;
    }

    // key id list
    TiXmlNode * p_node = NULL;
    TiXmlNode * p_keyid_list = NULL;

    p_keyid_list = p_xml_kdm->
        FirstChild("KeyIdList");
    if(p_keyid_list == 0)
    {
        fprintf(stderr, "getKdmInfo: key id list not found[%s:%d]" ,ST_INFO);
        return -ERR_KDM_NO_KEY_ID_LIST;
    }

    p_node = p_keyid_list->
        FirstChild("TypedKeyId");
    if( p_node == 0)
    {
        p_node = p_keyid_list->
            FirstChild("KeyId");
        if( p_node == 0)
        {
            fprintf(stderr, "getKdmInfo: key id not found[%s:%d]" ,ST_INFO);
            return -ERR_KDM_NO_KEY_UUID;
        }
        else
        {
            i = 0;
            // get number first
            for( p_key = p_node->ToElement(); 
                 p_key != 0;
                 p_key = p_key->NextSiblingElement("KeyId"), i++)
            {
                p_txt = p_key->FirstChild()->ToText();
                if( p_txt == 0)
                {
                    fprintf(stderr, "getKdmInfo: key id [%d] not found[%s:%d]", i ,ST_INFO);
                    ret = -ERR_KDM_NO_KEY_UUID;
                    break;
                }

                KdmEncKey enc_key;
                if( !ParseUuid(enc_key.key_uuid_, p_txt->Value()))
                {
                    fprintf(stderr, "ERR:Kdm::Open: key id [%d] \"%s\" not a uuid\n", i, p_txt->Value());
                    ret = -ERR_KDM_BAD_KEY_UUID;
                    break;
                }
                list_enc_key_.push_back(enc_key);

            }
            if(ret)
            {
                return ret;
            }
        }//end if( p_node == 0) else
    }
    else
    {
        // get number first
        for(p_key = p_node->ToElement(), i=0;
            p_key != 0;
            i++, p_key = p_key->NextSiblingElement("TypedKeyId"))
        {
            p_txt = p_key->
                FirstChild("KeyId")->
                FirstChild()->
                ToText();
            if( p_txt == 0)
            {
                fprintf(stderr, "getKdmInfo: key id [%d] not found[%s:%d]", i ,ST_INFO);
                ret = -ERR_KDM_NO_KEY_UUID;
                break;
            }

            KdmEncKey enc_key;
            if( !ParseUuid(enc_key.key_uuid_, p_txt->Value()))
            {
                fprintf(stderr, "ERR:Kdm::Open: key id [%d] \"%s\" not a uuid\n", i, p_txt->Value());
                ret = -ERR_KDM_BAD_KEY_UUID;
                break;
            }
            list_enc_key_.push_back(enc_key);
        }

        if(ret)
        {
            return ret;
        }
    }

    //fprintf( stderr, "Kdm::Open key id list OK\n");    

    // encrypted value
    if(use_etm)
    {
        p_elem = xml_handle.
            FirstChild("etm:DCinemaSecurityMessage").
            FirstChild("etm:AuthenticatedPrivate").
            FirstChild("enc:EncryptedKey").Element();
    }
    else
    {
        p_elem = xml_handle.
            FirstChild("DCinemaSecurityMessage").
            FirstChild("AuthenticatedPrivate").
            FirstChild("enc:EncryptedKey").Element();
    }
    if( !p_elem )
    {
        fprintf( stderr, "ERR:Kdm::Open: encrypted key not found\n");
        return -ERR_KDM_NO_ENCRYPTED_KEY;
    }

    ret = 0;
    i = 0;
    std::list<KdmEncKey>::iterator iter_begin, iter_end = list_enc_key_.end();

    for(p_key = p_elem, iter_begin = list_enc_key_.begin();
        iter_begin != iter_end && p_key != 0;
        i++, iter_begin ++, p_key = p_key->NextSiblingElement("enc:EncryptedKey"))
    {
        
        TiXmlElement *p_cd = p_key->FirstChildElement( "enc:CipherData");
        if( p_cd == 0)
        {
            fprintf( stderr, "ERR:Kdm::Open: cipher data[%d] not found\n", i);
            ret = -ERR_KDM_NO_CIPHER_DATA;
            break;
        }
        TiXmlElement *p_cv = p_cd->FirstChildElement("enc:CipherValue");
        if( p_cv == 0)
        {
            fprintf( stderr, "ERR:Kdm::Open: cipher value[%d] not found\n", i);
            ret = -ERR_KDM_NO_CIPHER_VALUE;
            break;
        }
        p_txt = p_cv->FirstChild()->ToText();
        if( p_txt == 0)
        {
            fprintf( stderr, "ERR:Kdm::Open: cipher value[%d] not found\n",i);
            ret = -ERR_KDM_NO_CIPHER_VALUE;
            break;
        }
        unsigned int out_size = 0,alloc_size = 0;
        void *p_data = base64_dec( p_txt->Value(), &out_size, &alloc_size);
        if( p_data == 0 || out_size < 256)
        {
            if( p_data) 
            {
                free(p_data);
            }
            fprintf( stderr, "ERR:Kdm::Open: cipher value[%d] bad format out=%u, alloc=%u\n", i, out_size, alloc_size);
            ret = -ERR_KDM_BAD_CIPHER_VALUE;
            break;
        }
        KdmEncKey &enc_key = *iter_begin;
        memcpy( enc_key.enc_key_, p_data, 256);
        free(p_data);
    }
    if( ret == 0)
    {
        if( iter_begin != iter_end)
        {
            fprintf(stderr, "WRN:Kdm::Open: key id more than cipher value, ignored\n");
            while(iter_begin != iter_end)
            {
                std::list<KdmEncKey>::iterator iter = iter_begin;
                ++iter_begin;
                list_enc_key_.erase(iter);
            }
        }
        else if( p_key != 0 )
        {
            fprintf( stderr, "WRN:Kdm::Open: key id less than cipher value[%d], ignored\n", i);
        }
    }
    else
    {
        return ret;
    }

    //fprintf( stderr, "Kdm::Open enc key list OK\n");
    return 0;
}

Kdm::Kdm(void)
{
    memset( msg_uuid_, 0, sizeof(msg_uuid_));
    memset( cpl_uuid_, 0, sizeof(cpl_uuid_));
    nv_after_ = 0;
    nv_before_ = 0;
}

Kdm::~Kdm(void)
{
    Close();
}

void Kdm::Close(void)
{
    memset( msg_uuid_, 0, sizeof(msg_uuid_));
    memset( cpl_uuid_, 0, sizeof(cpl_uuid_));
    content_title_.clear();
    nv_after_ = nv_before_ = 0;
    list_dec_key_.clear();
    list_enc_key_.clear();
}


void Kdm::Print( FILE *pf)
{
    int i;

    if( !IsOpen())
    {
        fprintf( pf, "msg_uuid = N/A\n");
        return;
    }

    fprintf( pf, "msg_uuid=");
    for(i=0;i<16;i++) fprintf(pf, "%02X", msg_uuid_[i]);
    fprintf( pf, "\n");

    fprintf( pf, "cpl_uuid=");
    for(i=0;i<16;i++) fprintf(pf, "%02X", cpl_uuid_[i]);
    fprintf( pf, "\n");

    fprintf( pf, "    time= [%0llu, %llu]\n", nv_before_, nv_after_);    

    fprintf( pf, "content=%s\n", content_title_.c_str());

    {
        std::list<KdmEncKey>::iterator iter, iter_end = list_enc_key_.end();
        int n;
        for( iter = list_enc_key_.begin(), n=0; iter!=iter_end; ++iter, ++n)
        {
            fprintf( pf, "enc_key[%d]\n", n);
            fprintf( pf, "    key_uuid=");
            for(i=0;i<16;i++) fprintf(pf, "%02X", iter->key_uuid_[i]);
            fprintf( pf, "\n");
            fprintf( pf, "    encd_key=");
            for(i=0;i<256;i++)
            {
                if(i%32==0) fprintf(pf, "\n        ");
                fprintf(pf, "%02X", iter->enc_key_[i]);
            }
            fprintf(pf, "\n");
        }
    }
    if( IsDec())
    {
        int ret = Check();

        if( ret != 0)
        {
            fprintf(pf, "ERR:check fail [%d]\n", ret);
        }

        std::list<KdmDecKey>::iterator iter, iter_end = list_dec_key_.end();
        int n;
        for( iter = list_dec_key_.begin(), n=0; iter!=iter_end; ++iter, ++n)
        {
            fprintf( pf, "dec_key[%d]\n", n);

            fprintf( pf, "    key_uuid=");
            for(i=0;i<16;i++) fprintf(pf, "%02X", iter->key_uuid_[i]);
            fprintf( pf, "\n");

            fprintf( pf, "    cpl_uuid=");
            for(i=0;i<16;i++) fprintf(pf, "%02X", iter->cpl_uuid_[i]);
            fprintf( pf, "\n");

            fprintf( pf, "    aes_key=");
            for(i=0;i<16;i++) fprintf(pf, "%02X", iter->aes_key_[i]);
            fprintf( pf, "\n");

            fprintf( pf, "    time= [%0llu, %llu]\n", iter->nv_before_, iter->nv_after_);
        }    
    }
    else
    {
        fprintf( pf, "not decrypted\n");
    }
}

int Kdm::Dec(const char *pri_fn)
{
    int ret = 0;
    char *key_buf = NULL;
    unsigned int key_len = 0;

    int i = 0;
    char utc_buf[26];
    std::list<KdmEncKey>::iterator iter, iter_end = list_enc_key_.end();
    
    if( !IsOpen())
    {
        ret = -ERR_KDM_NOT_OPEN;
        goto end__;
    }
    if( IsDec())
    {
        goto end__;
    }

    // st get key buffer
    ret = get_key_buffer(&key_buf, &key_len, pri_fn);
    if(ret < 0)
    {
        fprintf(stderr, "ERR:Kdm::Dec: get key buffer err\n");
        ret = -ERR_KDM_DECRYPT_KEY;
        goto end__;
    }

    for( iter = list_enc_key_.begin(), i=0; iter != iter_end; ++iter, ++i)
    {
        KdmDecKey dec_key;
        unsigned char dec_buf[256];
        int dec_size = 0;
        memset( dec_buf, 0, sizeof(dec_buf));
//        dec_size = rsa_decrypt(pri_fn, iter->enc_key_, dec_buf);
        if(0)
        {
            FILE * fpkey;
            fpkey = fopen("kdm.bin", "w");
            fwrite(iter->enc_key_, sizeof(iter->enc_key_), 1, fpkey);
            fclose(fpkey);
        }

        dec_size = rsa_decrypt_from_buffer(key_buf, key_len, iter->enc_key_, dec_buf);

        if( dec_size < 0)
        {
            fprintf( stderr, "ERR:Kdm::Dec: decryt[%d] fail\n", i);
            ret = -ERR_KDM_DECRYPT_KEY;
            goto end__;
        }
        if( dec_size == 138)
        {
            memcpy( dec_key.cpl_uuid_, dec_buf + 36 , 16);
            
            memcpy( dec_key.key_uuid_, dec_buf + 56 , 16);

            memcpy( utc_buf, dec_buf + 72, 25);
            utc_buf[25] = 0;
            if( ParseUtc(&(dec_key.nv_before_), utc_buf) < 0)
            {
                ret = -ERR_KDM_BAD_UTC_NV_BEFORE;
                goto end__;
            }

            memcpy( utc_buf, dec_buf + 97, 25);
            utc_buf[25] = 0;
            if( ParseUtc(&(dec_key.nv_after_), utc_buf) < 0)
            {
                ret = -ERR_KDM_BAD_UTC_NV_AFTER;
                goto end__;
            }

            memcpy( dec_key.aes_key_, dec_buf + 122, 16);            
        }
        else if(dec_size == 134)
        {
            memcpy( dec_key.cpl_uuid_, dec_buf + 36 , 16);
            memcpy( dec_key.key_uuid_, dec_buf + 52 , 16);

            memcpy( utc_buf, dec_buf + 68, 25);
            utc_buf[25] = 0;
            if( ParseUtc(&(dec_key.nv_before_), utc_buf) < 0)
            {
                ret = -ERR_KDM_BAD_UTC_NV_BEFORE;
                goto end__;
            }

            memcpy( utc_buf, dec_buf + 93, 25);
            utc_buf[25] = 0;
            if( ParseUtc(&(dec_key.nv_after_), utc_buf) < 0)
            {
                ret = -ERR_KDM_BAD_UTC_NV_AFTER;
                goto end__;
            }

            memcpy( dec_key.aes_key_, dec_buf + 118, 16);
        }
        else
        {
            fprintf( stderr, "ERR:Kdm::Dec: invalid decryped size=%d [%d]\n", dec_size, i);
            ret = -ERR_KDM_BAD_DECRYPT_KEY;
            goto end__;
        }
        list_dec_key_.push_back(dec_key);
    }

end__:
    if(key_buf)
    {
        free(key_buf);key_buf = NULL;
    }
    return ret;
}

int Kdm::Check(void) const
{
    if( !IsDec()) return -ERR_KDM_NOT_DEC;
    if( list_dec_key_.size() != list_enc_key_.size()) return -ERR_KDM_NOT_BALANCE;
    std::list<KdmDecKey>::const_iterator dec_iter, dec_iter_end = list_dec_key_.end();
    std::list<KdmEncKey>::const_iterator enc_iter, enc_iter_end = list_enc_key_.end();
    for( dec_iter = list_dec_key_.begin(), enc_iter = list_enc_key_.begin();
         dec_iter != dec_iter_end;
         ++ dec_iter, ++ enc_iter)
    {
        if( memcmp( dec_iter->key_uuid_, enc_iter->key_uuid_, 16) != 0)
        {
            return -ERR_KDM_KEY_UUID_NOT_EQUAL;
        }
        if( memcmp( dec_iter->cpl_uuid_, cpl_uuid_, 16) != 0)
        {
            return -ERR_KDM_CPL_UUID_NOT_EQUAL;
        }
        if( dec_iter->nv_before_ != nv_before_)
        {
            return -ERR_KDM_NV_BEFORE_NOT_EQUAL;
        }
        if( dec_iter->nv_after_ != nv_after_)
        {
            return -ERR_KDM_NV_AFTER_NOT_EQUAL;
        }
    }
    return 0;
}

