#include "pch.h"
#include "CMfcFileEditBrowser.h"
BEGIN_MESSAGE_MAP(CMfcFileEditBrowser, CMFCEditBrowseCtrl)
	ON_WM_DROPFILES()
END_MESSAGE_MAP()


void CMfcFileEditBrowser::OnDropFiles(HDROP hDropInfo)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	if (hDropInfo)
	{
		int nDrag; //拖拽文件的数量
		nDrag = DragQueryFile(hDropInfo, 0xFFFFFFFF, NULL, 0);
		if (nDrag == 1)
		{
			// 被拖拽的文件的文件名
			TCHAR Path[MAX_PATH + 1] = { 0 };
			// 得到被拖拽的文件名
			DragQueryFile(hDropInfo, 0, Path, MAX_PATH);
			// 把文件名显示出来
			SetWindowTextW(Path);
			DragFinish(hDropInfo);
		}
		else
		{
			MessageBox(L"只能拖拽一个文件！", L"DllInject", MB_OK | MB_ICONWARNING);
		}

		CMFCEditBrowseCtrl::OnDropFiles(hDropInfo);
	}
}
