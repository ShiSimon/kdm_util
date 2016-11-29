#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "dirent.h"
#include <string.h>
#include <malloc.h>

#include "kdm_util.hpp"

static char *strDup(const char *str);

// my strdup
static char *strDup(const char *str)
{
    char *ret = (char*)malloc(strlen(str) + 1);
    if( ret )
    {
	strcpy( ret, str);
    }
    return ret;
}

#if 0
Kdm *getKdmByCpl(const unsigned char cpl_uuid[16], const char *kdm_root, const char *pri_fn)
{
    Kdm *p_kdm = new Kdm;
    int ret = 0;
    char cpl_buf[64];

    // create the kdm path
    PrintUuid( cpl_buf, cpl_uuid, UUID_NO_PREFIX);
    std::string kdm_glob( kdm_root);
    kdm_glob.append( cpl_buf);
    kdm_glob.append( "/*.kdm.xml");

    // glob the *.kdm.xml
    glob_t glob_buf;
    ret = glob( kdm_glob.c_str(), 0, NULL, &glob_buf);
    if( ret != 0)		// err;
    {
	delete p_kdm;
	return 0;
    }

    unsigned int i;
    for( i = 0; i < glob_buf.gl_pathc; i++)
    {
	ret = p_kdm->Open( glob_buf.gl_pathv[i]);
	if( ret < 0)
	{
	    continue;
	}
	ret = p_kdm->Dec(pri_fn);
	if( ret < 0)
	{
	    p_kdm->Close();
	    continue;
	}
	if( p_kdm->Check() < 0) // 检查失败
	{
	    p_kdm->Close();
	    continue;
	}

        // 时间不在范围内
	unsigned long long time_now = (unsigned long long)time(0);
	if( time_now >= p_kdm->GetNotValidBefore()
	    && time_now <= p_kdm->GetNotValidAfter())
	{
	    p_kdm->Close();
	    continue;
	}

        // 找到，准备退出
	globfree(&glob_buf);	
	return p_kdm;
    }

    delete p_kdm;
    globfree(&glob_buf);
    return 0;
}
#endif

int parseKdm(const char *kdm_file, std::list<KdmParam> &list_kdm, int flag, const char *pri_fn)
{
    if( flag & KDMUTIL_NO_STORE_KDM)
    {
        Kdm *p_kdm = new Kdm;
        if( p_kdm->Open(kdm_file) == 0)
        {
            KdmParam kdm_param;
            kdm_param.path_ = strDup(kdm_file);
            kdm_param.p_kdm_ = 0;
            if( kdm_param.path_ == 0)
            {
                delete p_kdm;
                return -1;
            }
            list_kdm.push_back(kdm_param);
            p_kdm->Close();
            delete p_kdm;
        }
        else
        {
            delete p_kdm;
            return -2;
        }
    } // end of 不保存 kdm
    else
    {
        Kdm *p_kdm = new Kdm;
        if( p_kdm->Open(kdm_file) == 0) {                // 打开成功
            KdmParam kdm_param;                
            if( flag & KDMUTIL_DO_DEC)
            {
                if( p_kdm->Dec(pri_fn) < 0) // 解码失败
                {
                    if( flag & KDMUTIL_NO_DEC_FAIL) // 解码失败不要存储
                    {
                        kdm_param.p_kdm_ = 0;
                        delete p_kdm;
                    }
                    else
                    {
                        kdm_param.p_kdm_ = p_kdm;
                    }
                }
                else        // 解码成功
                {
                    if( flag & KDMUTIL_NO_CHECK_FAIL) // 检查失败也要存储
                    {
                        kdm_param.p_kdm_ = p_kdm;
                    }
                    else if( p_kdm->Check() == 0)
                    {
                        kdm_param.p_kdm_ = p_kdm;
                    }
                    else
                    {
                        kdm_param.p_kdm_ = 0;
                        delete p_kdm;
                    }
                }
            } // 
            else            // 不用解码
            {
                kdm_param.p_kdm_ = p_kdm;
            }
	    
            kdm_param.path_ = strDup(kdm_file); // use my strDup instead of strdup, which not exist in sigma
            if( kdm_param.path_ == 0)
            {
                delete p_kdm;
                return -3;
            }
            list_kdm.push_back(kdm_param);
        } // endof 打开成功
        else
        {
            delete p_kdm;
            return -4;
        }
    }
    return 0;
}

int scanKdms(const char *kdm_root, std::list<KdmParam> &list_kdm, int flag, const char *pri_fn)
{
    int i,n;
	DIR *dir;
	struct dirent *ptr;
	char tmp_name[1024];

	if ((dir = opendir(kdm_root)) == NULL)
	{
		fprintf(stderr, "open kdm dir error!\n");
		return -1;
	}
	while ((ptr = readdir(dir)) != NULL)
	{
		char * p = strrchr(ptr->d_name, '.');
		if (strcmp(p, ".") || strcmp(p, "..") || strcmp(p, ".xml"))
		{
			continue;
		}
		snprintf(tmp_name, sizeof(tmp_name), "%s/%s", kdm_root, ptr->d_name);
		parseKdm(tmp_name, list_kdm, flag, pri_fn);

	}
	closedir(dir);
	return 0;
}

void clearKdmsParamList( std::list<KdmParam> &list_kdm)
{
    std::list<KdmParam>::iterator iter, iter_end = list_kdm.end();

    for( iter = list_kdm.begin(); iter != iter_end; ++iter)
    {
        free( iter->path_);
        delete iter->p_kdm_;
    }
    list_kdm.clear();
}
