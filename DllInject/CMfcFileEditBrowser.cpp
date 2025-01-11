#include "pch.h"
#include "CMfcFileEditBrowser.h"
BEGIN_MESSAGE_MAP(CMfcFileEditBrowser, CMFCEditBrowseCtrl)
	ON_WM_DROPFILES()
END_MESSAGE_MAP()


void CMfcFileEditBrowser::OnDropFiles(HDROP hDropInfo)
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	if (hDropInfo)
	{
		int nDrag; //��ק�ļ�������
		nDrag = DragQueryFile(hDropInfo, 0xFFFFFFFF, NULL, 0);
		if (nDrag == 1)
		{
			// ����ק���ļ����ļ���
			TCHAR Path[MAX_PATH + 1] = { 0 };
			// �õ�����ק���ļ���
			DragQueryFile(hDropInfo, 0, Path, MAX_PATH);
			// ���ļ�����ʾ����
			SetWindowTextW(Path);
			DragFinish(hDropInfo);
		}
		else
		{
			MessageBox(L"ֻ����קһ���ļ���", L"DllInject", MB_OK | MB_ICONWARNING);
		}

		CMFCEditBrowseCtrl::OnDropFiles(hDropInfo);
	}
}
