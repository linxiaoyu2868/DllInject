
// DllInjectDlg.cpp: 实现文件
//

#include "pch.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include "framework.h"
#include "DllInject.h"
#include "DllInjectDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#pragma region 提权
bool AdjustPrevileges()
{
	BOOL bResult = FALSE;
	static const auto& RtlAdjustPrivilege = (DWORD(NTAPI*)(int, BOOL, BOOL, PBOOL))GetProcAddress(GetModuleHandleW(L"Ntdll"), "RtlAdjustPrivilege");
	if (!RtlAdjustPrivilege)
	{
		return false;
	}

	DWORD NtStatus = RtlAdjustPrivilege(20, TRUE, FALSE, &bResult);
	SetLastError(NtStatus);
	return bResult;
}
#pragma endregion

#pragma region 注入
BOOL InjectDll(DWORD dwProcessId, LPCTSTR szDllPath)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL)
	{
		return FALSE;
	}

	LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, _tcslen(szDllPath) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
	{
		CloseHandle(hProcess);
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, _tcslen(szDllPath) * sizeof(TCHAR), NULL))
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	LPTHREAD_START_ROUTINE pfnThreadRtn = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pfnThreadRtn == NULL)
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pRemoteBuf, 0, NULL);
	if (hThread == NULL)
	{
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}
#pragma endregion

#pragma region 取出模块地址
HMODULE FindModuleInProcess(HANDLE hProcess, LPCWSTR moduleName) {
	DWORD cbNeeded;
	HMODULE* hMods;
	unsigned int i;

	// 第一步：获取模块数量  
	if (!EnumProcessModules(hProcess, NULL, 0, &cbNeeded)) {
		return NULL;
	}

	// 第二步：分配足够的内存来保存所有模块的句柄  
	hMods = (HMODULE*)HeapAlloc(GetProcessHeap(), 0, cbNeeded);
	if (hMods == NULL) {
		return NULL;
	}

	// 第三步：获取所有模块的句柄  
	if (EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded)) {
		// 第四步：遍历模块句柄，查找匹配的模块名称  
		for (i = 0; cbNeeded > 0; i++) {
			wchar_t szModName[MAX_PATH];
			if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
				if (wcscmp(szModName, moduleName) == 0) {
					HeapFree(GetProcessHeap(), 0, hMods);
					return hMods[i]; // 找到匹配项，返回模块句柄  
				}
			}
			cbNeeded -= sizeof(HMODULE);
		}
	}

	// 清理  
	HeapFree(GetProcessHeap(), 0, hMods);
	return NULL; // 没有找到匹配的模块  
}
#pragma endregion

#pragma region 进程PID获取

BOOL GetProcessIdByProcessName(LPCWSTR ProcessName)
{
	HWND hWnd{};
	//1.创建进程快照
	HANDLE hSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS,            //遍历进程快照1
		0);                            //进程PID
	if (INVALID_HANDLE_VALUE == hSnap)
	{
		MessageBox(hWnd, L"创建进程快照失败！", L"Message", MB_OK | MB_ICONERROR);
		return 0;
	}

	//2.获取第一条进程快照信息
	PROCESSENTRY32  stcPe = { sizeof(stcPe) };
	if (Process32First(hSnap, &stcPe))
	{

		//3.循环遍历进程Next
		do {

			//获取快照信息
			USES_CONVERSION;

			if (!lstrcmp(stcPe.szExeFile, ProcessName))
			{
				//4.关闭句柄
				CloseHandle(hSnap);
				return stcPe.th32ProcessID;
			}

		} while (Process32Next(hSnap, &stcPe));

	}

	//4.关闭句柄
	CloseHandle(hSnap);
	return 0;
}
#pragma endregion

#pragma region 管理员询问
BOOL IsUserAnAdmin()
{
	BOOL bElevated = FALSE;	//是否管理员
	//1.得到自身进程的权限访问令牌
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))

		return FALSE;


	//2.获取进程相关运行权限
	TOKEN_ELEVATION tokenEle{};
	DWORD dwRetLen = 0;
	if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen))
	{
		//如果接受到的内存大小和结构体成正比例，代表接受完整的进程权限数据
		if (dwRetLen == sizeof(tokenEle))
		{
			//取是否管理员布尔值
			bElevated = tokenEle.TokenIsElevated;
		}
	}
	//关闭进程令牌
	CloseHandle(hToken);
	//返回是否OK
	return bElevated;
}
#pragma endregion

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CDllInjectDlg 对话框



CDllInjectDlg::CDllInjectDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DLLINJECT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDllInjectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_BUTTON1, InjectButton);
	DDX_Control(pDX, IDC_EDIT1, ProcessNameEdit);
	DDX_Control(pDX, IDC_MFCEDITBROWSE1, DllPathEdit);
	DDX_Control(pDX, IDC_EDIT2, ExportMessageDlg);
}

BEGIN_MESSAGE_MAP(CDllInjectDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CDllInjectDlg::OnBnClickedButton1)
//	ON_WM_DROPFILES()
ON_EN_CHANGE(IDC_EDIT1, &CDllInjectDlg::OnEnChangeEdit1)
ON_EN_CHANGE(IDC_MFCEDITBROWSE1, &CDllInjectDlg::OnEnChangeMfceditbrowse1)
ON_WM_DROPFILES()
ON_WM_CLOSE()
END_MESSAGE_MAP()


// CDllInjectDlg 消息处理程序

BOOL CDllInjectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	if (IsUserAnAdmin())
		SetWindowText(L"MainWindow(管理员)");

	CMFCEditBrowseCtrl* prog = (CMFCEditBrowseCtrl*)GetDlgItem(IDC_MFCEDITBROWSE1); //get edit browse control ID
	prog->EnableFileBrowseButton(_T("选择动态链接库"), _T("Dynamic Link Library|*.dll|")); //filter file but *.bmp
	AdjustPrevileges();
	InjectButton.SetWindowTextW(L"未选择dll和程序");
	InjectButton.EnableWindow(FALSE);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CDllInjectDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CDllInjectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CDllInjectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CDllInjectDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	int nLength{};
	CString ProcessName;
	CString DllPath;
	ProcessNameEdit.GetWindowTextW(ProcessName);
	DllPathEdit.GetWindowTextW(DllPath);
	LPCTSTR szDllPath = DllPath;
	GetDlgItem(IDC_EDIT2)->SetWindowTextW(NULL);
	ExportMessageDlg.SetWindowTextW(L"要注入的进程:" + ProcessName + L"\r\n查找进程:");
	//MessageBox(szDllPath);
	CEdit* ExportMessageDlg = (CEdit*)GetDlgItem(IDC_EDIT2);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessIdByProcessName(ProcessName + L".exe"));
	if (hProcess == NULL)
	{
		
		nLength = ExportMessageDlg->GetWindowTextLengthW();
		//选定文本末端
		ExportMessageDlg->SetSel(nLength, nLength);
		ExportMessageDlg->ReplaceSel(L"FAIL\r\n进程不存在\r\n");
	}
	else
	{
		nLength = ExportMessageDlg->GetWindowTextLengthW();
		//选定文本末端
		ExportMessageDlg->SetSel(nLength, nLength);
		ExportMessageDlg->ReplaceSel(L"SUCESS!\r\n分配虚拟内存空间:");
		LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, _tcslen(DllPath) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
		if (pRemoteBuf == NULL)
		{
			CloseHandle(hProcess);
			nLength = ExportMessageDlg->GetWindowTextLengthW();
			//选定文本末端
			ExportMessageDlg->SetSel(nLength, nLength);
			ExportMessageDlg->ReplaceSel(L"FAIL\r\n内存分配失败\r\n");
		}
		else
		{
			nLength = ExportMessageDlg->GetWindowTextLengthW();
			//选定文本末端
			ExportMessageDlg->SetSel(nLength, nLength);
			ExportMessageDlg->ReplaceSel(L"SUCESS!\r\n写入进程内存空间:");
			if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, _tcslen(szDllPath) * sizeof(TCHAR), NULL))
			{
				VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
				CloseHandle(hProcess);
				nLength = ExportMessageDlg->GetWindowTextLengthW();
				//选定文本末端
				ExportMessageDlg->SetSel(nLength, nLength);
				ExportMessageDlg->ReplaceSel(L"FAIL\r\n写入进程内存失败\r\n");
			}
			else
			{
				nLength = ExportMessageDlg->GetWindowTextLengthW();
				//选定文本末端
				ExportMessageDlg->SetSel(nLength, nLength);
				ExportMessageDlg->ReplaceSel(L"SUCESS!\r\n远程调用链接库:");
				HMODULE hModule = GetModuleHandleW(L"kernel32.dll");
				LPTHREAD_START_ROUTINE pfnThreadRtn = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "LoadLibraryW");
				if (pfnThreadRtn == NULL)
				{
					VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
					CloseHandle(hProcess);
					CEdit* ExportMessageDlg = (CEdit*)GetDlgItem(IDC_EDIT2);
					int nLength = ExportMessageDlg->GetWindowTextLengthW();
					//选定文本末端
					ExportMessageDlg->SetSel(nLength, nLength);
					ExportMessageDlg->ReplaceSel(L"FAIL\r\n远程调用动态链接库失败\r\n");
				}
				else
				{
					nLength = ExportMessageDlg->GetWindowTextLengthW();
					//选定文本末端
					ExportMessageDlg->SetSel(nLength, nLength);
					ExportMessageDlg->ReplaceSel(L"SUCESS!\r\n创建远程线程启动动态链接库:");
					HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pRemoteBuf, 0, NULL);
					if (hThread == NULL)
					{
						VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
						CloseHandle(hProcess);
						CEdit* ExportMessageDlg = (CEdit*)GetDlgItem(IDC_EDIT2);
						int nLength = ExportMessageDlg->GetWindowTextLengthW();
						//选定文本末端
						ExportMessageDlg->SetSel(nLength, nLength);
						ExportMessageDlg->ReplaceSel(L"FAIL\r\n动态链接库注入失败！！！\r\n");
					}
					else
					{
						CString Handel;
						//HMODULE hDll = GetModuleHandleW(DllPath.Right(DllPath.GetLength() - DllPath.ReverseFind('\\') - 1));
						WaitForSingleObject(hThread, 1);
						Handel.Format(L"%u", (DWORD)FindModuleInProcess(hProcess, DllPath.Right(DllPath.GetLength() - DllPath.ReverseFind('\\') - 1)));
						nLength = ExportMessageDlg->GetWindowTextLengthW();
						//选定文本末端
						ExportMessageDlg->SetSel(nLength, nLength);
						ExportMessageDlg->ReplaceSel(L"SUCESS!\r\n动态链接库注入成功！\r\n模块句柄:" + Handel);
						//WaitForSingleObject(hThread, INFINITE);
						VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
						CloseHandle(hThread);
						CloseHandle(hProcess);
						FreeLibrary(hModule);
					}

				}

			}
			
		}
		
	}

	/*if (InjectDll(GetProcessIdByProcessName(ProcessName + L".exe"), DllPath))
	{
		MessageBox(L"注入成功！", L"Message", MB_OK | MB_ICONINFORMATION);
	}
	else
	{
		MessageBox(L"注入失败！！！", L"Message", MB_OK | MB_ICONERROR);
	}*/
}

void CDllInjectDlg::OnEnChangeEdit1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。
	CString local,local1;
	ProcessNameEdit.GetWindowTextW(local);
	DllPathEdit.GetWindowTextW(local1);
	if (local == local1 && local.GetLength() == 0)
	{
		InjectButton.SetWindowTextW(L"未选择dll和程序");
		InjectButton.EnableWindow(FALSE);
	}
	else if (local.GetLength() == 0 && local1.GetLength() != 0)
	{
		InjectButton.SetWindowTextW(L"未选择注入的程序");
		InjectButton.EnableWindow(FALSE);
	}
	else if (local.GetLength() != 0 && local1.GetLength() == 0)
	{
		InjectButton.SetWindowTextW(L"未选择注入的dll");
		InjectButton.EnableWindow(FALSE);
	}
	else
	{
		InjectButton.SetWindowTextW(L"注入");
		InjectButton.EnableWindow(TRUE);
	}
	// TODO:  在此添加控件通知处理程序代码
}


void CDllInjectDlg::OnEnChangeMfceditbrowse1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。
	CString local, local1;
	ProcessNameEdit.GetWindowTextW(local);
	DllPathEdit.GetWindowTextW(local1);
	if (local == local1 && local.GetLength() == 0)
	{
		InjectButton.SetWindowTextW(L"未选择dll和程序");
		InjectButton.EnableWindow(FALSE);
	}
	else if (local.GetLength() == 0 && local1.GetLength() != 0)
	{
		InjectButton.SetWindowTextW(L"未选择注入的程序");
		InjectButton.EnableWindow(FALSE);
	}
	else if (local.GetLength() != 0 && local1.GetLength() == 0)
	{
		InjectButton.SetWindowTextW(L"未选择注入的dll");
		InjectButton.EnableWindow(FALSE);
	}
	else
	{
		InjectButton.SetWindowTextW(L"注入");
		InjectButton.EnableWindow(TRUE);
	}
	// TODO:  在此添加控件通知处理程序代码
}


void CDllInjectDlg::OnDropFiles(HDROP hDropInfo)
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
			DllPathEdit.SetWindowTextW(Path);
			DragFinish(hDropInfo);
		}
		else
		{
			MessageBox(_T("只能拖拽一个文件！"));
		}
		CDialogEx::OnDropFiles(hDropInfo);
	}
}


void CDllInjectDlg::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值

	CDialogEx::OnClose();
}
