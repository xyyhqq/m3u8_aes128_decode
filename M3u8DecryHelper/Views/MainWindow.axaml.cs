using Avalonia.Controls;
using System.Reflection.Metadata;

namespace M3u8DecryHelper.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        GlobalConstant.MainWindow = this;
    }
}