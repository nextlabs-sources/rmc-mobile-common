//
//  nxcommon.h
//  nxrmc
//
//  Created by Kevin on 15/4/28.
//  Copyright (c) 2015年 nextlabs. All rights reserved.
//

#ifndef __nxcommon_h__
#define __nxcommon_h__

#include <stdio.h>

#include <string>

namespace nxcommon {
    /** Convert binary sid to string sid.
     *  This funciton doesn same thing with ConvertSidToStringSid (Windows API). After search on internet, I haven't find that a function which can convert binary sid to string on IOS, Android, then I created this function by myself. refer to http://blogs.msdn.com/b/oldnewthing/archive/2004/03/15/89753.aspx
     *  @param bsid point to a byte stream which stores sid with binary format
     *  @param len  specifies the length of bsid
     *  @return returns sid with string format if successfully. otherwise returns empty string.
     */
    std::string convertToStringSid(const unsigned char* bsid, const int len)
    {
        if (len < 8)  // at least 8 bytes
        {
            return "";
        }
        
        char buf[1024] = {0};
        std::string sid("S");
        
        // revision
        int revision = bsid[0];
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "-%d", revision);
        sid.append(buf);
        
        // 6 types
        unsigned char temp[6] = {0};
        for (int i = 0; i < 6; ++i)
        {
            temp[6 - i - 1] = bsid[2 + i];
        }
        long long d3 = 0;
        memcpy(&d3, temp, 6);
        
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "-%lld", d3);
        sid.append(buf);
        
        // 32bit (4bytes) dashes
        int dashes = static_cast<int>(bsid[1]);  // second byte determines dash number. dashes = total dashes - 2
        
        if (dashes * 4 != len - 8)
        {
            return "";  // wrong format
        }
        
        for (int i = 0; i < dashes; ++i)
        {
            unsigned int v = 0;
            memcpy(&v, bsid + 8 + i * 4, 4);
            
            memset(buf, 0, sizeof(buf));
            sprintf(buf, "-%u", v);
            sid.append(buf);
        }
        
        return sid;
    }

}


#endif
