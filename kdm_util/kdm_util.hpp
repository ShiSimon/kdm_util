#ifndef INCLUDED_KDM_HPP
#define INCLUDED_KDM_HPP

#include <list>
#include "kdm.hpp"

/// get Kdm according to the cpl_uuid
///
/// parse the 'kdm_root' dir, decode the kdm with the cpl_uuid value
/// and check it. return the first correct kdm.
/// Used in decode phase.
/// 
/// @param[in] cpl_uuid target cpl uuid
/// @param[in] kdm_root kdm root dir
/// @param[in] flag     flag
//Kdm *getKdmByCpl(const unsigned char cpl_uuid[16], const char *kdm_root, const char *pri_fn);

struct KdmParam
{
    char *path_;
    Kdm *p_kdm_;
};

enum
{
    KDMUTIL_NO_STORE_KDM  = 1,
    KDMUTIL_NO_SUB_DIR    = 2,
    KDMUTIL_DO_DEC        = 4,
    KDMUTIL_NO_DEC_FAIL   = 8,
    KDMUTIL_NO_CHECK_FAIL = 16,
};
    
/// scan all kdm in kdm_root dir
///
/// scan the *.xml in the kdm_root dir, including the sub dirs.
/// only the regular file and symbolic link is checked.
/// Used in copy phase.
///
/// @param[in] kdm_root     : 
/// @param[in,out] list_kdm :
/// @param[in] flag         :
///
/// KDMUTIL_NO_STORE_KDM  = 1: 不存储 KDM，只获得文件名
/// KDMUTIL_NO_SUB_DIR    = 2: 不扫描子目录
/// KDMUTIL_DO_DEC        = 4: 当需要存储时，对KDM进行解码
/// KDMUTIL_NO_DEC_FAIL   = 8: 如果解码失败，则不进入列表
/// KDMUTIL_NO_CHECK_FAIL = 16: 如果解码成功，但Check失败，则不进入列表
int parseKdm(const char *kdm_file, std::list<KdmParam> &list_kdm, int flag, const char *pri_fn);
int scanKdms(const char *kdm_root, std::list<KdmParam> &list_kdm, int flag, const char *pri_fn);

void clearKdmsParamList( std::list<KdmParam> &list_kdm);



#endif
