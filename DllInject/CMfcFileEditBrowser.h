#pragma once
#include <afxeditbrowsectrl.h>
class CMfcFileEditBrowser :
    public CMFCEditBrowseCtrl
{
public:
    DECLARE_MESSAGE_MAP()
    afx_msg void OnDropFiles(HDROP hDropInfo);
};

