//
//  NXPolicyEngine.h
//  nxrmc
//
//  Created by Kevin on 15/6/5.
//  Copyright (c) 2015年 nextlabs. All rights reserved.
//

#ifndef __nxrmc__NXPolicyEngine__
#define __nxrmc__NXPolicyEngine__

#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <iterator>

#include "xmlparser/include/libxml/parser.h"

namespace nxl {
    
    class NXPolicyEngine
    {
    public:
        explicit NXPolicyEngine(const std::string& policyContent);

        long getRights(const std::string& username,
                       const std::string& userId,
                       const std::map<std::string, std::vector<std::string>>& mapTags,
                       const char* content,
                       int size,
                       std::multimap<std::string, std::vector<std::pair<std::string, std::string>>>& Obligations,
                       std::vector<std::pair<std::string, std::string>>& hitPolicy);

    private:
        NXPolicyEngine(const NXPolicyEngine&);
        NXPolicyEngine& operator= (const NXPolicyEngine&);
        
        const std::string _policyContent;

    private:
        struct resStruct
        {
            std::string name;
            std::string method;
            std::string value;
        };

    private:
        std::map<std::string, bool> getAllRights(const std::string& username,
                                                 const std::string& userID,
                                                 const std::map<std::string, std::vector<std::string>>& mapTags,
                                                 const char* content,
                                                 int size,
                                                 std::multimap<std::string, std::vector<std::pair<std::string, std::string>>>& Obligations,
                                                 std::vector<std::pair<std::string, std::string>>& hitPolicy);
        bool getUserMapInfo(xmlNodePtr node, const std::string& userID, std::string& info);
        void getAllPolicyInfo(xmlNodePtr node,
                              const std::string& userInfo,
                              const std::map<std::string, std::vector<std::string>>& mapTags,
                              std::map<std::string, bool>& Rights,
                              std::multimap<std::string, std::vector<std::pair<std::string, std::string>>>& Obligations,
                              std::vector<std::pair<std::string, std::string>>& hitPolicy);
        bool getEachPolicyInfo(xmlNodePtr node,
                               const std::map<std::string, std::vector<resStruct>>& resInfo,
                               const std::string& userInfo,
                               const std::map<std::string, std::vector<std::string>>& mapTags,
                               std::map<std::string, bool>& Rights,
                               std::multimap<std::string, std::vector<std::pair<std::string, std::string>>>& Obligations,
                               std::vector<std::pair<std::string, std::string>>& hitPolicy);

    private:
        xmlNodePtr getPolicybundleNode(xmlNodePtr root);
        std::map<std::string, std::vector<resStruct>> getResourcesInfo(xmlNodePtr node);
        void GetPolicyInfoAndUserGroup(xmlNodePtr node, std::set<std::string>& RightName, std::string& Id, std::string& Name, std::string& UserGroup);
        void ParseRightName(const std::string& strValue, std::set<std::string>& vecRightName);
        void ParseString(const std::string& strValue, std::set<std::string>& vecValues);
        bool GetRightAndOb(xmlNodePtr node,
                                 const std::map<std::string, std::vector<resStruct>>& resInfo,
                                 const std::map<std::string, std::vector<std::string>>& mapTags,
                                 std::multimap<std::string, std::vector<std::pair<std::string, std::string>>>& Obligations);
        bool GetResRight(const std::map<std::string, std::vector<resStruct>>& resInfo,
                         const std::set<std::string>& vecValues,
                         const std::map<std::string, std::vector<std::string>>& mapTags);

    private:
        static const std::string m_cpRightView;
        static const std::string m_cpRightClassify;
        static const std::string m_cpRightCopy;
        static const std::string m_cpRightSend;
        static const std::string m_cpRightShare;
        static const std::set<std::string> m_setRights;
        static const std::set<std::string> m_setResFilter;

        static const std::string m_cpObligationOverlay;
        static const std::set<std::string> m_setObligationsFilter;

        static const int m_RightNumber = 5;
    };
}  // namespace nxl

#endif /* defined(__nxrmc__NXPolicyEngine__) */
