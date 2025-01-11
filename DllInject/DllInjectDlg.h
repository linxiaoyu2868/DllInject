
// DllInjectDlg.h: 头文件
//

#pragma once
#include "CMfcFileEditBrowser.h"


// CDllInjectDlg 对话框
class CDllInjectDlg : public CDialogEx
{
// 构造
public:
	CDllInjectDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DLLINJECT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CButton InjectButton;
	afx_msg void OnBnClickedButton1();
	CEdit ProcessNameEdit;
	//CMFCEditBrowseCtrl DllPathEdit;
	CMfcFileEditBrowser DllPathEdit;
//	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnEnChangeEdit1();
	afx_msg void OnEnChangeMfceditbrowse1();
	CEdit ExportMessageDlg;
	afx_msg void OnDropFiles(HDROP hDropInfo);
	afx_msg void OnClose();
};
