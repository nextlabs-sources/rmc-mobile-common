//
//  NXPolicyEngine.cpp
//  nxrmc
//
//  Created by Kevin on 15/6/5.
//  Copyright (c) 2015年 nextlabs. All rights reserved.
//

#include "NXPolicyEngine.h"

namespace nxl {
    const std::string NXPolicyEngine::m_cpRightView = "RIGHT_VIEW";
    const std::string NXPolicyEngine::m_cpRightClassify = "RIGHT_CLASSIFY";
    const std::string NXPolicyEngine::m_cpRightCopy = "RIGHT_COPY";
    const std::string NXPolicyEngine::m_cpRightSend = "RIGHT_SEND";
    const std::string NXPolicyEngine::m_cpRightShare = "RIGHT_SHARE";

    const std::set<std::string> NXPolicyEngine::m_setRights = {m_cpRightView, m_cpRightClassify, m_cpRightCopy, m_cpRightSend, m_cpRightShare};
    const std::set<std::string> NXPolicyEngine::m_setResFilter = {"NAME", "ACCESS_DATE", "CREATED_DATE", "DIRECTORY", "ISDIRECTORY",
                                                                  "MODIFIED_DATE", "OWNER_LDAP_GROUP", "SIZE", "TYPE", "CONTENT", "CONTENTTYPE"};

    const std::string NXPolicyEngine::m_cpObligationOverlay = "OB_OVERLAY";
    const std::set<std::string> NXPolicyEngine::m_setObligationsFilter = {m_cpObligationOverlay};

    NXPolicyEngine::NXPolicyEngine(const std::string& policyContent) : _policyContent(policyContent)
    {
        
    }

    long NXPolicyEngine::getRights(const std::string& username,
                                   const std::string& userId,
                                   const std::map<std::string, std::vector<std::string>>& mapTags,
                                   const char* content,
                                   int size,
                                   std::multimap<std::string, std::vector<std::pair<std::string, std::string>>>& Obligations,
                                   std::vector<std::pair<std::string, std::string>>& hitPolicy)
    {
        int Rights = 0;

        xmlInitParser();

        std::map<std::string, bool> mapRights = getAllRights(username, userId, mapTags, content, size, Obligations, hitPolicy);

        xmlCleanupParser();

        if(mapRights[m_cpRightView])
        {
            Rights |= 1;

            if(mapRights[m_cpRightClassify])
            {
                Rights |= 2;
            }

            if(mapRights[m_cpRightCopy])
            {
                Rights |= 4;
            }

            if(mapRights[m_cpRightSend])
            {
                Rights |= 8;
            }

            if(mapRights[m_cpRightShare])
            {
                Rights |= 16;
            }
        }

        return Rights;
    }

    std::map<std::string, bool> NXPolicyEngine::getAllRights(const std::string& username,
                                                             const std::string& userID,
                                                             const std::map<std::string, std::vector<std::string>>& mapTags,
                                                             const char* content,
                                                             int size,
                                                             std::multimap<std::string, std::vector<std::pair<std::string, std::string>>>& Obligations,
                                                             std::vector<std::pair<std::string, std::string>>& hitPolicy)
    {
        std::map<std::string, bool> mapRights;

        xmlDocPtr doc = xmlReadMemory(content, size, NULL, NULL, 0);
        if (doc != NULL )
        {
            xmlNodePtr root = xmlDocGetRootElement(doc);
            if (root != NULL)
            {
                xmlNodePtr PolicybundleNode = getPolicybundleNode(root);

                if(PolicybundleNode != nullptr)
                {
                    std::string userInfo;

                    if(getUserMapInfo(PolicybundleNode, userID, userInfo))
                    {
                        getAllPolicyInfo(PolicybundleNode, userInfo, mapTags, mapRights, Obligations, hitPolicy);
                    }
                }
            }

            xmlFreeDoc(doc);
        }

        return mapRights;
    }

    bool NXPolicyEngine::getUserMapInfo(xmlNodePtr node, const std::string& userID, std::string& info)
    {
        xmlNodePtr UserGroupMapNode = nullptr;

        for (xmlNodePtr cur_node = node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"USERGROUPMAP")) {
                UserGroupMapNode = cur_node;
                break;
            }
        }

        if (UserGroupMapNode == nullptr)
        {
            return false;
        }

        for (xmlNodePtr cur_node = UserGroupMapNode->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"USERMAP")) {
                const xmlChar* sID = xmlGetProp(cur_node, (const xmlChar *)"id");
                if (sID != NULL && 0 == xmlStrcmp(sID, (const xmlChar *)userID.c_str())) {
                    const xmlChar* content = xmlNodeGetContent(cur_node);
                    std::string strcontent = (const char*)content;
                    while(true)
                    {
                        std::string::size_type pos = 0;
                        if ((pos = strcontent.find(" ", pos)) != std::string::npos)
                        {
                            strcontent.replace(pos, 1, "");
                        }
                        else
                        {
                            break;
                        }
                    }
                    info = "," + strcontent + ",";
                    return true;
                }
            }
        }

        info = ",,";
        return true;
    }

    xmlNodePtr NXPolicyEngine::getPolicybundleNode(xmlNodePtr root)
    {
        xmlNodePtr AgentUpdatesNode = nullptr;

        for (xmlNodePtr cur_node = root->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"AgentUpdates")) {
                AgentUpdatesNode = cur_node;
                break;
            }
        }

        if (AgentUpdatesNode == nullptr)
        {
            return nullptr;
        }

        xmlNodePtr PolicyDeploymentBundleNode = nullptr;

        for (xmlNodePtr cur_node = AgentUpdatesNode->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"policyDeploymentBundle")) {
                PolicyDeploymentBundleNode = cur_node;
                break;
            }
        }

        if (PolicyDeploymentBundleNode == nullptr)
        {
            return nullptr;
        }

        xmlNodePtr PolicyBundleNode = nullptr;

        for (xmlNodePtr cur_node = PolicyDeploymentBundleNode->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"POLICYBUNDLE")) {
                PolicyBundleNode = cur_node;
                break;
            }
        }

        return PolicyBundleNode;
    }

    void NXPolicyEngine::getAllPolicyInfo(xmlNodePtr node,
                                          const std::string& userInfo,
                                          const std::map<std::string, std::vector<std::string>>& mapTags,
                                          std::map<std::string, bool>& Rights,
                                          std::multimap<std::string, std::vector<std::pair<std::string, std::string>>>& Obligations,
                                          std::vector<std::pair<std::string, std::string>>& hitPolicy)
    {
        xmlNodePtr PolicySetNode = nullptr;

        for (xmlNodePtr cur_node = node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"POLICYSET")) {
                PolicySetNode = cur_node;
                break;
            }
        }

        if (PolicySetNode == nullptr)
        {
            return;
        }

        std::map<std::string, std::vector<resStruct>> resInfo = getResourcesInfo(node);

        std::vector<xmlNodePtr> FirstLevelPolicy;
        std::vector<xmlNodePtr> OtherLevelPolicy;

        for (xmlNodePtr cur_node = PolicySetNode->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"POLICY")) {
                const xmlChar* sName = xmlGetProp(cur_node, (const xmlChar *)"name");
                if (sName != NULL) {
                    const xmlChar* pFirstFound = xmlStrchr(sName, '/');
                    if(pFirstFound != NULL){
                        const xmlChar* pSecondFound = xmlStrchr(pFirstFound + 1, '/');
                        if(pSecondFound != NULL){
                            OtherLevelPolicy.push_back(cur_node);
                        }
                        else{
                            FirstLevelPolicy.push_back(cur_node);
                        }
                    }
                }
            }
        }

        std::map<xmlNodePtr, std::vector<xmlNodePtr>> AllPolicies;

        for(std::vector<xmlNodePtr>::const_iterator ci = FirstLevelPolicy.begin(); ci!= FirstLevelPolicy.end(); ++ci) {
            std::vector<xmlNodePtr> SubPolicy;

            const xmlChar* sName = xmlGetProp(*ci, (const xmlChar *)"name");
            xmlChar* sPrefix = xmlStrncatNew(sName, (const xmlChar*)"/", 1);
            for(std::vector<xmlNodePtr>::const_iterator thisci = OtherLevelPolicy.begin(); thisci!= OtherLevelPolicy.end();) {
                const xmlChar* sthisName = xmlGetProp(*thisci, (const xmlChar *)"name");
                if(0 == xmlStrncmp(sPrefix, sthisName, xmlStrlen(sPrefix))) {
                    SubPolicy.push_back(*thisci);
                    thisci = OtherLevelPolicy.erase(thisci);
                }
                else {
                    ++thisci;
                }
            }
            xmlFree(sPrefix);

            AllPolicies.insert(std::make_pair(*ci, SubPolicy));
        }

        for(std::vector<xmlNodePtr>::const_iterator ci = OtherLevelPolicy.begin(); ci!= OtherLevelPolicy.end(); ++ci) {
            std::vector<xmlNodePtr> SubPolicy;
            AllPolicies.insert(std::make_pair(*ci, SubPolicy));
        }

        for(std::map<xmlNodePtr, std::vector<xmlNodePtr>>::const_iterator ci = AllPolicies.begin(); ci!= AllPolicies.end(); ++ci) {
            std::multimap<std::string, std::vector<std::pair<std::string, std::string>>> ob;

            if(getEachPolicyInfo(ci->first, resInfo, userInfo, mapTags, Rights, ob, hitPolicy)){
                bool bMatchSubPolicy = false;

                for(std::vector<xmlNodePtr>::const_iterator thisci = ci->second.begin(); thisci!= ci->second.end(); ++thisci) {
                    std::multimap<std::string, std::vector<std::pair<std::string, std::string>>> thisob;

                    if(getEachPolicyInfo(*thisci, resInfo, userInfo, mapTags, Rights, thisob, hitPolicy)){
                        bMatchSubPolicy = true;
                        copy(thisob.begin(), thisob.end(), std::inserter(Obligations, Obligations.begin()));
                    }
                }

                if(!bMatchSubPolicy) {
                    copy(ob.begin(), ob.end(), std::inserter(Obligations, Obligations.begin()));
                }
            }
        }
    }

    std::map<std::string, std::vector<NXPolicyEngine::resStruct>> NXPolicyEngine::getResourcesInfo(xmlNodePtr node)
    {
        xmlNodePtr ComponentsNode = nullptr;

        for (xmlNodePtr cur_node = node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"COMPONENTS")) {
                ComponentsNode = cur_node;
                break;
            }
        }

        if (ComponentsNode == nullptr)
        {
            return std::map<std::string, std::vector<resStruct>>();
        }

        xmlNodePtr ResourcesNode = nullptr;

        for (xmlNodePtr cur_node = ComponentsNode->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"RESOURCES")) {
                ResourcesNode = cur_node;
                break;
            }
        }

        std::map<std::string, std::vector<resStruct>> Results;

        for (xmlNodePtr cur_node = ResourcesNode->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"RESOURCE")) {

                const xmlChar* sID = xmlGetProp(cur_node, (const xmlChar *)"id");
                if (sID != NULL) {

                    std::string strID = (const char*)sID;
                    if (!strID.empty())
                    {
                        std::vector<resStruct> VecResStruct;

                        for (xmlNodePtr temp_node = cur_node->children; temp_node; temp_node = temp_node->next)
                        {
                            if (temp_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(temp_node->name, (const xmlChar *)"PROPERTY")) {

                                const xmlChar* sName = xmlGetProp(temp_node, (const xmlChar *)"name");
                                const xmlChar* sMethod = xmlGetProp(temp_node, (const xmlChar *)"method");
                                const xmlChar* sValue = xmlGetProp(temp_node, (const xmlChar *)"value");

                                if (sName != NULL && sMethod != NULL && sValue != NULL) {

                                    std::string strName = (const char*)sName;
                                    std::string strMethod = (const char*)sMethod;
                                    std::string strValue = (const char*)sValue;

                                    std::transform(strName.begin(), strName.end(),strName.begin(), toupper);
                                    std::transform(strValue.begin(), strValue.end(),strValue.begin(), toupper);

                                    if (!strName.empty() && !strMethod.empty() && !strValue.empty() && m_setResFilter.end() == m_setResFilter.find(strName))
                                    {
                                        resStruct TempREsStruct = {strName, strMethod, strValue};
                                        VecResStruct.push_back(TempREsStruct);
                                    }
                                }
                            }
                        }

                        if(!VecResStruct.empty())
                        {
                            Results[strID] = VecResStruct;
                        }
                    }
                }
            }
        }

        return  Results;
    }

    bool NXPolicyEngine::getEachPolicyInfo(xmlNodePtr node,
                                           const std::map<std::string,std::vector<resStruct>>& resInfo,
                                           const std::string& userInfo,
                                           const std::map<std::string, std::vector<std::string>>& mapTags,
                                           std::map<std::string, bool>& Rights,
                                           std::multimap<std::string, std::vector<std::pair<std::string, std::string>>>& Obligations,
                                           std::vector<std::pair<std::string, std::string>>& hitPolicy)
    {
        std::set<std::string> RightName;
        std::string UserGroup;
        std::string Id;
        std::string Name;

        GetPolicyInfoAndUserGroup(node, RightName, Id, Name, UserGroup);

        if(RightName.empty())
        {
            return false;
        }

        bool bBelongTo = true;

        if(!UserGroup.empty())
        {
            if(std::string::npos == userInfo.find(UserGroup))
            {
                bBelongTo = false;
            }
        }

        if(!bBelongTo)
        {
            return false;
        }

        if(GetRightAndOb(node, resInfo, mapTags, Obligations))
        {
            for(std::set<std::string>::const_iterator ci = RightName.begin(); ci != RightName.end(); ++ci)
            {
                Rights[*ci] = true;
            }
            hitPolicy.push_back(std::make_pair(Id, Name));

            return true;
        }

        return false;
    }

    void NXPolicyEngine::GetPolicyInfoAndUserGroup(xmlNodePtr node, std::set<std::string>& RightName, std::string& Id, std::string& Name, std::string& UserGroup)
    {
        const xmlChar* srights = xmlGetProp(node, (const xmlChar *)"rights");
        if(srights != nullptr)
        {
            ParseRightName((const char*)srights, RightName);
        }

        const xmlChar* sid = xmlGetProp(node, (const xmlChar *)"id");
        if(sid != nullptr)
        {
            Id = (const char*)sid;
        }

        const xmlChar* sname = xmlGetProp(node, (const xmlChar *)"name");
        if(sname != nullptr)
        {
            Name = (const char*)sname;
        }

        const xmlChar* susergroup = xmlGetProp(node, (const xmlChar *)"usergroup");
        if(susergroup != nullptr)
        {
            UserGroup = "," + std::string((const char*)susergroup) + ",";
        }
    }

    void NXPolicyEngine::ParseRightName(const std::string& strValue, std::set<std::string>& vecRightName)
    {
        std::set<std::string> Temp;

        ParseString(strValue, Temp);

        set_intersection( Temp.begin(), Temp.end(), m_setRights.begin(), m_setRights.end() ,std::inserter(vecRightName, vecRightName.begin()));
    }

    void NXPolicyEngine::ParseString(const std::string& strValue, std::set<std::string>& vecValues)
    {
        std::size_t n = 0;

        while (n < strValue.size())
        {
            std::size_t m = strValue.find(",", n);

            std::string temp = strValue.substr(n, m - n);
            if (!temp.empty())
            {
                vecValues.insert(temp);
            }

            if (m == std::string::npos)
            {
                break;
            }

            n = m + 1;
        }
    }

    bool NXPolicyEngine::GetRightAndOb(xmlNodePtr node,
                                             const std::map<std::string, std::vector<resStruct>>& resInfo,
                                             const std::map<std::string, std::vector<std::string>>& mapTags,
                                             std::multimap<std::string, std::vector<std::pair<std::string, std::string>>>& Obligations)
    {
        std::multimap<std::string, std::vector<std::pair<std::string, std::string>>> ob;

        for (xmlNodePtr cur_node = node->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"CONDITION")) {
                const xmlChar* stype = xmlGetProp(cur_node, (const xmlChar *)"type");
                if (stype != NULL && 0 == xmlStrcmp(stype, (const xmlChar *)"res"))
                {
                    bool bExclude = false;

                    const xmlChar* sexclude = xmlGetProp(cur_node, (const xmlChar *)"exclude");
                    if (sexclude != NULL && 0 == xmlStrcmp(sexclude, (const xmlChar *)"true"))
                    {
                        bExclude = true;
                    }

                    std::set<std::string> vecRes;
                    ParseString((const char*)xmlNodeGetContent(cur_node), vecRes);

                    bool bAllow = GetResRight(resInfo, vecRes, mapTags);

                    if(!bExclude)
                    {
                        if(!bAllow)
                        {
                            return false;
                        }
                    }
                    else
                    {
                        if(bAllow)
                        {
                            return false;
                        }
                    }
                }
            }
            else if(cur_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(cur_node->name, (const xmlChar *)"OBLIGATION"))
            {
                const xmlChar* sobname = xmlGetProp(cur_node, (const xmlChar *)"name");
                if(sobname != NULL)
                {
                    std::string strobname = (const char*)sobname;
                    if(m_setObligationsFilter.end() != std::find(m_setObligationsFilter.begin(), m_setObligationsFilter.end(), strobname))
                    {
                        std::vector<std::pair<std::string, std::string>> values;
                        for (xmlNodePtr value_node = cur_node->children; value_node; value_node = value_node->next)
                        {
                            if(value_node->type == XML_ELEMENT_NODE && 0 == xmlStrcmp(value_node->name, (const xmlChar *)"PARAM"))
                            {
                                const xmlChar* sName = xmlGetProp(value_node, (const xmlChar *)"name");
                                const xmlChar* sValue = xmlGetProp(value_node, (const xmlChar *)"value");

                                if (sName != NULL && sValue != NULL)
                                {
                                    values.push_back(std::make_pair((const char*)sName, (const char*)sValue));
                                }
                            }
                        }

                        ob.insert(std::make_pair(strobname, values));
                    }
                }
            }
        }

        copy(ob.begin(), ob.end(), std::inserter(Obligations, Obligations.begin()));

        return true;
    }

    bool NXPolicyEngine::GetResRight(const std::map<std::string, std::vector<resStruct>>& resInfo,
                                     const std::set<std::string>& vecValues,
                                     const std::map<std::string, std::vector<std::string>>& mapTags)
    {
        for(std::set<std::string>::const_iterator ci = vecValues.begin(); ci != vecValues.end(); ++ci)
        {
            std::map<std::string, std::vector<resStruct>>::const_iterator position = resInfo.find(*ci);

            if(position != resInfo.end())
            {
                bool isBreak = false;

                for(std::vector<resStruct>::const_iterator res = position->second.begin(); res!= position->second.end(); ++res)
                {
                    std::map<std::string, std::vector<std::string>>::const_iterator cifind = mapTags.find(res->name);
                    if(cifind == mapTags.end())
                    {
                        isBreak = true;
                        break;
                    }
                    else
                    {
                        if (0 == res->method.compare("EQ"))
                        {
                            if(cifind->second.end() == std::find(cifind->second.begin(), cifind->second.end(), res->value))
                            {
                                isBreak = true;
                                break;
                            }
                        }
                        else
                        {
                            if(cifind->second.end() != std::find(cifind->second.begin(), cifind->second.end(), res->value))
                            {
                                isBreak = true;
                                break;
                            }
                        }
                    }
                }

                if(!isBreak)
                {
                    return true;
                }
            }
        }

        return false;
    }

}  // namespace