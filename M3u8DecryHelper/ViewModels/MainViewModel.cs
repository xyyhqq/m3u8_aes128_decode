using Avalonia.Controls;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.Input;
using M3u8DecryHelper.Views;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Windows.Input;
using Avalonia.Data.Core;

namespace M3u8DecryHelper.ViewModels;

public partial class MainViewModel : ViewModelBase
{
    public string Tip => "m3u8 aes-128 解密";

    private string _M3u8FileName;

    public string M3u8FileName
    {
        get { return _M3u8FileName; }
        set { _M3u8FileName = value; OnPropertyChanged(); }
    }  
    private string _KeyFile;

    public string KeyFile
    {
        get { return _KeyFile; }
        set { _KeyFile = value; OnPropertyChanged(); }
    }
    
    private string _EncryVideoFile;

    public string EncryVideoFile
    {
        get { return _EncryVideoFile; }
        set { SetProperty(ref _EncryVideoFile, value); }
    }

    private string _SaveLocation;

    public string SaveLocation
    {
        get { return _SaveLocation; }
        set { SetProperty(ref _SaveLocation, value); }
    }
    private string _Logs;

    public string Logs
    {
        get { return _Logs; }
        set { SetProperty(ref _Logs, value); }
    }
   
    public ICommand Selectm3u8FileCommand => new RelayCommand(ExecuteSelectm3u8FileCommand);
    public ICommand SelectKeyFileCommand => new RelayCommand(ExecuteSelectKeyFileCommand);

    private async void ExecuteSelectKeyFileCommand()
    {
        // 从当前控件获取 TopLevel。或者，您也可以使用 Window 引用。
        var topLevel = TopLevel.GetTopLevel(GlobalConstant.MainWindow);

        // 启动异步操作以打开对话框。
        var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Open Text File",
            AllowMultiple = false
        });

        if (files.Count >= 1)
        {
            // 打开第一个文件的读取流。
            KeyFile = files[0].Path.LocalPath;
        }
    }

    public ICommand SelectmEncryFileCommand => new RelayCommand(ExecuteSelectEncryFileCommand);
    public ICommand SaveFileCommand => new RelayCommand(ExecuteSaveFileCommand);
    public ICommand DecrptCommand => new RelayCommand(ExecuteDecrptCommand);

    private void ExecuteDecrptCommand()
    {
        try
        {
            Logs = "";
            if (string.IsNullOrEmpty(M3u8FileName))
            {
                Logs += $"m3u8文件为空{Environment.NewLine}";
                return;
            }
            if (string.IsNullOrEmpty(KeyFile))
            { Logs += $"key文件为空{Environment.NewLine}";
                return;
            } 
            if (string.IsNullOrEmpty(EncryVideoFile))
            { Logs += $"视频为空{Environment.NewLine}";
                return;
            }  if (string.IsNullOrEmpty(EncryVideoFile))
            {
                Logs += $"保存路径为空{Environment.NewLine}";
                return;
            } 
            if (string.IsNullOrEmpty(SaveLocation))
            {
                return;
            }
            //1 获取m3u8中的iv信息
            string m3u8encodeKeyContent = File.ReadAllText(M3u8FileName);
            //2 读取m3u8头信息指向的加密key文件
            byte[] encodeBufferKey = File.ReadAllBytes(KeyFile);
            //3 加密ts视频的路径
            byte[] encodeBuffer = File.ReadAllBytes(EncryVideoFile);
            //4 解密ts视频为mp4保存视频路径
            string saveFileName = SaveLocation;

            string pattern = @"IV=0x([A-Fa-f0-9]+)";
            Match match = Regex.Match(m3u8encodeKeyContent, pattern);
            string ivValue = "";
            if (match.Success)
            {
                ivValue = match.Groups[1].Value; // 捕获组的内容
            }
            else
            { Logs += $"m3u8 文件异常{Environment.NewLine}";
                throw new ArgumentException("m3u8 文件异常");
            }
            string key = Convert.ToHexString(encodeBufferKey);
            byte[] decodeBuffer = Decrypt(encodeBuffer, key, ivValue);
            File.WriteAllBytes(saveFileName, decodeBuffer);
            Logs += $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} 文件{saveFileName},转码，保存成功{Environment.NewLine}";
        }
        catch (Exception e)
        {   Logs += $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} 解密失败{Environment.NewLine}";
            Console.WriteLine(e);
           
        }
        
    }

    private byte[] Decrypt(byte[] cipherTextBytes, string key16, string iv16)
    {
        // 确保字符串长度是偶数
        if (key16.Length % 2 == 1)
        {
            Logs += $"key16 错误{Environment.NewLine}";
            throw new ArgumentException("The key16 string length must be even.");
        }
        if (iv16.Length % 2 == 1)
        { 
            Logs += $"iv16 错误{Environment.NewLine}";
            throw new ArgumentException("The iv16 string length must be even.");
        }

        byte[] buffkey = new byte[key16.Length / 2];
        for (int i = 0; i < key16.Length; i += 2)
        {
            var tempkey = key16.Substring(i, 2);
            buffkey[i / 2] = Convert.ToByte(tempkey, 16);
        }
        byte[] buffiv = new byte[key16.Length / 2];
        for (int i = 0; i < iv16.Length; i += 2)
        {
            var tempkey = iv16.Substring(i, 2);
            buffiv[i / 2] = Convert.ToByte(tempkey, 16);
        }
        // 确保密钥和IV长度正确（128位，即16字节）
        byte[] keyBytes = buffkey.ToArray();
        byte[] ivBytes = buffiv.ToArray();

        // 创建RijndaelManaged对象用于解密
        using (RijndaelManaged aes = new RijndaelManaged())
        {
            aes.Key = keyBytes;
            aes.IV = ivBytes;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            // 创建解密器
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            // 创建MemoryStream以用于解密
            using (MemoryStream msDecrypt = new MemoryStream(cipherTextBytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    // 读取解密后的字节
                    byte[] decryptedBytes = new byte[cipherTextBytes.Length];
                    csDecrypt.Read(decryptedBytes, 0, decryptedBytes.Length);

                    return decryptedBytes;
                }
            }
        }
    }

    private async void ExecuteSaveFileCommand()
    {
        // 从当前控件获取 TopLevel。或者，您也可以使用 Window 引用。
        var topLevel = TopLevel.GetTopLevel(GlobalConstant.MainWindow);
        var fil = new List<FilePickerFileType>();
        var filePickerFileType = new FilePickerFileType("mp4文件");
        filePickerFileType  .Patterns = new[] { "*.mp4" };
        fil .Add(filePickerFileType);
        // 启动异步操作以打开对话框。
        var file = await topLevel.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save Text File",
            FileTypeChoices = fil
          
        });
        
        if (file is not null)
        {
            SaveLocation = file.Path.LocalPath;
        }
     
        
    }

    private async void ExecuteSelectEncryFileCommand()
    {
        // 从当前控件获取 TopLevel。或者，您也可以使用 Window 引用。
        var topLevel = TopLevel.GetTopLevel(GlobalConstant.MainWindow);

        // 启动异步操作以打开对话框。
        var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Open Text File",
            AllowMultiple = false
        });

        if (files.Count >= 1)
        {
            // 打开第一个文件的读取流。
            EncryVideoFile = files[0].Path.LocalPath;
        }
    }

    private async void ExecuteSelectm3u8FileCommand()
    {
        // 从当前控件获取 TopLevel。或者，您也可以使用 Window 引用。
        var topLevel = TopLevel.GetTopLevel(GlobalConstant.MainWindow);

        // 启动异步操作以打开对话框。
        var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Open Text File",
            AllowMultiple = false
        });

        if (files.Count >= 1)
        {
            // 打开第一个文件的读取流。
            M3u8FileName = files[0].Path.LocalPath;
        }
    }
}